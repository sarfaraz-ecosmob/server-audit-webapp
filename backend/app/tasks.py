import os
import threading
from datetime import datetime

from .celery_app import celery_app
from .database import SessionLocal
from . import models, crypto
from .config import settings
from .services import ssh_executor
from .services.report_parser import parse_summary


def _build_target(server: models.Server) -> ssh_executor.SSHTarget:
    sudo_password = (
        crypto.decrypt_password(server.sudo_password_encrypted)
        if server.sudo_password_encrypted
        else None
    )

    if server.auth_type == models.AuthType.password:
        password = crypto.decrypt_password(server.secret_encrypted)
        # No explicit sudo password on file? Reuse the SSH login password —
        # this is what most people expect when they only entered one
        # username/password pair for a sudo-capable account.
        if sudo_password is None:
            sudo_password = password
        return ssh_executor.SSHTarget(
            host=server.host, port=server.port, username=server.username,
            password=password, sudo_password=sudo_password,
        )

    key, passphrase = crypto.decrypt_private_key(server.secret_encrypted)
    # Key-based login has no password to fall back on for sudo — if none was
    # explicitly set, sudo runs non-interactively (`sudo -n`), which needs
    # NOPASSWD sudo already configured on the target.
    return ssh_executor.SSHTarget(
        host=server.host, port=server.port, username=server.username,
        private_key_pem=key, private_key_passphrase=passphrase,
        sudo_password=sudo_password,
    )


@celery_app.task(
    bind=True,
    # Celery-enforced wall-clock caps — independent of, and a real backstop
    # for, the per-command socket timeouts inside ssh_executor (those only
    # fire on total silence; a script that prints periodically but is
    # otherwise stuck would never trip them).
    soft_time_limit=settings.install_task_hard_timeout_seconds,
    time_limit=settings.install_task_hard_timeout_seconds + 30,
)
def install_tools_task(self, run_id: str):
    db = SessionLocal()
    try:
        run = db.query(models.AuditRun).get(run_id)
        server = run.server
        run.status = models.RunStatus.running
        db.commit()

        target = _build_target(server)
        try:
            result = ssh_executor.install_tools(target, run.requested_tools)
            run.log_tail = (result.stdout + "\n" + result.stderr)[-4000:]
            run.status = (
                models.RunStatus.completed if result.exit_code == 0 else models.RunStatus.failed
            )
        except Exception as e:  # noqa: BLE001
            run.status = models.RunStatus.failed
            run.log_tail = f"Install failed before/without remote output: {e}"
        finally:
            run.finished_at = datetime.utcnow()
            server.last_run_id = run.id
            db.commit()
    finally:
        db.close()


@celery_app.task(bind=True, soft_time_limit=90, time_limit=120)
def check_tools_task(self, run_id: str):
    db = SessionLocal()
    try:
        run = db.query(models.AuditRun).get(run_id)
        server = run.server
        run.status = models.RunStatus.running
        db.commit()

        target = _build_target(server)
        try:
            result = ssh_executor.check_tools(target)
            run.log_tail = (result.stdout + "\n" + result.stderr)[-4000:]
            run.status = models.RunStatus.completed
            # crude parse of `--check` output lines like "lynis: installed"
            status_map = {}
            for line in result.stdout.splitlines():
                for tool in ssh_executor.ALLOWED_TOOLS:
                    if line.lower().startswith(tool):
                        status_map[tool] = "installed" in line.lower()
            server.installed_tools = status_map
        except Exception as e:  # noqa: BLE001
            run.status = models.RunStatus.failed
            run.log_tail = f"Connection/check failed: {e}"
        finally:
            run.finished_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


@celery_app.task(
    bind=True,
    soft_time_limit=settings.audit_task_hard_timeout_seconds,
    time_limit=settings.audit_task_hard_timeout_seconds + 60,
)
def run_audit_task(self, run_id: str):
    db = SessionLocal()
    try:
        run = db.query(models.AuditRun).get(run_id)
        server = run.server
        run.status = models.RunStatus.running
        db.commit()

        target = _build_target(server)
        health_env_content = None
        if server.health_env_encrypted:
            health_env_content = crypto.decrypt_text(server.health_env_encrypted)

        try:
            # `run.flags` was computed by the API layer when the run was created
            # (see routers/servers.py) and is the single source of truth for
            # exactly what gets passed to server_audit.sh.
            flags = run.flags or []
            web_targets = [flags[i + 1] for i, f in enumerate(flags) if f == "-u"]

            # Read-only side channel: tails this run's own audit_run.log for
            # server_audit.sh's real phase markers so the UI can show genuine
            # progress. Stopped (and joined) before we touch run.summary
            # below, so it can never race the final report-parsed summary.
            stop_poll = threading.Event()
            poller = threading.Thread(
                target=ssh_executor.poll_audit_phase,
                args=(target, settings.remote_workdir, run_id, stop_poll),
                daemon=True,
            )
            poller.start()
            try:
                result, remote_output_dir, used_flags = ssh_executor.run_audit(
                    target,
                    web_targets=web_targets,
                    full_scan="--full-scan" in flags,
                    skip_nmap="-n" in flags,
                    skip_zap="-z" in flags,
                    skip_lynis="-l" in flags,
                    health_env_content=health_env_content,
                )
            finally:
                stop_poll.set()
                poller.join(timeout=5)

            run.log_tail = (result.stdout + "\n" + result.stderr)[-4000:]

            local_report_path = os.path.join(
                settings.report_storage_dir, str(server.id), f"{run.id}.html"
            )
            remote_log_path = ssh_executor.download_latest_report(
                target, remote_output_dir, local_report_path
            )
            run.report_path = local_report_path

            with open(local_report_path, "r", errors="replace") as f:
                html = f.read()
            run.summary = parse_summary(html)

            run.status = (
                models.RunStatus.completed if result.exit_code == 0 else models.RunStatus.failed
            )
            if result.exit_code != 0:
                # augment with fuller remote log for debugging
                remote_tail = ssh_executor.fetch_log_tail(target, remote_log_path)
                run.log_tail = (run.log_tail + "\n---- audit_run.log tail ----\n" + remote_tail)[-6000:]
        except Exception as e:  # noqa: BLE001
            run.status = models.RunStatus.failed
            run.log_tail = (run.log_tail or "") + f"\nAudit failed: {e}"
        finally:
            run.finished_at = datetime.utcnow()
            server.last_run_id = run.id
            db.commit()
    finally:
        db.close()
