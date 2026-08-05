"""
The ONLY code path that talks to a remote server over SSH.

By design this module exposes just three operations, each building its
remote command from a fixed template with strictly typed/whitelisted
arguments — never string-interpolating anything the end user typed freely
into a shell command:

    check_tools()      -> `./server_audit.sh --check`             (read-only)
    install_tools()     -> `./install_tools.sh --only <enum subset> --yes`
    run_audit()         -> `./server_audit.sh -s -o ... [-u ...] [flags]`
    poll_audit_phase()   -> tails the run's own audit_run.log (read-only),
                            never runs anything — see its docstring

No other remote command is ever constructed here or anywhere else in the
codebase. If you need a new capability, add a new narrowly-scoped method to
this file — do not add a generic "run arbitrary command" method.
"""
import base64
import io
import os
import posixpath
import re
import shlex
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Optional

import paramiko

from ..config import settings

ALLOWED_TOOLS = {"lynis", "nmap", "rkhunter", "zap-docker", "trivy", "jq"}

REMOTE_SCRIPTS = ["server_audit.sh", "gen_report.py", "install_tools.sh"]


@dataclass
class SSHTarget:
    host: str
    port: int
    username: str
    password: Optional[str] = None
    private_key_pem: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    # Password to feed to `sudo` on the remote host. Independent of the SSH
    # login password/key above — see resolution order in tasks._build_target.
    # None means: no password available for sudo, fall back to `sudo -n`
    # (requires passwordless/NOPASSWD sudo already configured on the target).
    sudo_password: Optional[str] = None


@dataclass
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float


class RemoteExecError(Exception):
    pass


@contextmanager
def ssh_connection(target: SSHTarget, timeout: int = 20):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs = dict(
            hostname=target.host,
            port=target.port,
            username=target.username,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            # Auth must be exactly what the person provided in the app —
            # never fall back to an SSH agent or scan the container's
            # (nonexistent) ~/.ssh for default keys. Without this, password
            # auth fails outright in a bare container because paramiko's
            # default key-search touches a ~/.ssh that doesn't exist there.
            look_for_keys=False,
            allow_agent=False,
        )
        if target.private_key_pem:
            pkey = paramiko.RSAKey.from_private_key(
                io.StringIO(target.private_key_pem),
                password=target.private_key_passphrase or None,
            )
            connect_kwargs["pkey"] = pkey
        else:
            connect_kwargs["password"] = target.password

        client.connect(**connect_kwargs)
        yield client
    finally:
        client.close()


def _run(
    client: paramiko.SSHClient, command: str, timeout: int, sudo_password: Optional[str] = None
) -> CommandResult:
    start = time.monotonic()
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=False)
    if sudo_password is not None:
        # Fed over the already-encrypted SSH channel's stdin, never as a
        # command-line argument (so it can't show up in `ps`) and never
        # logged. Paired with `sudo -S -p ''` below, which reads exactly
        # one line from stdin instead of prompting on a tty.
        stdin.write(sudo_password + "\n")
        stdin.flush()
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    return CommandResult(exit_code, out, err, time.monotonic() - start)


def _sudo_prefix(sudo_password: Optional[str]) -> str:
    """`sudo -S` reads the password from stdin (fed by _run above) with no
    prompt text (`-p ''`) so stdout/stderr stay clean. Falls back to
    `sudo -n` (non-interactive, fails immediately if a password would be
    needed) when no sudo password is available for this target."""
    return "sudo -S -p ''" if sudo_password else "sudo -n"


def ensure_remote_dir(client: paramiko.SSHClient, remote_dir: str):
    result = _run(client, f"mkdir -p {shlex.quote(remote_dir)}", timeout=15)
    if result.exit_code != 0:
        raise RemoteExecError(
            f"Could not create remote directory '{remote_dir}': "
            f"{(result.stderr or result.stdout).strip() or 'unknown error (exit code %d)' % result.exit_code}"
        )


def upload_scripts(client: paramiko.SSHClient, remote_dir: str):
    """Copy the bundled, checksummed scripts to the target. Never generated
    or user-editable — always the exact files shipped with this backend."""
    try:
        ensure_remote_dir(client, remote_dir)
        ensure_remote_dir(client, posixpath.join(remote_dir, "linux-health"))
        sftp = client.open_sftp()
        try:
            for fname in REMOTE_SCRIPTS:
                local_path = os.path.join(settings.scripts_dir, fname)
                remote_path = posixpath.join(remote_dir, fname)
                sftp.put(local_path, remote_path)
            local_health_dir = os.path.join(settings.scripts_dir, "linux-health")
            if os.path.isdir(local_health_dir):
                for fname in os.listdir(local_health_dir):
                    sftp.put(
                        os.path.join(local_health_dir, fname),
                        posixpath.join(remote_dir, "linux-health", fname),
                    )
        finally:
            sftp.close()
    except RemoteExecError:
        raise
    except (IOError, OSError) as e:
        # This is where a permission-denied write shows up — surfaced with
        # its own message so it's never confused with an SSH auth/connection
        # failure (the connection succeeded; this is a filesystem write).
        raise RemoteExecError(
            f"Connected over SSH, but could not write scripts to '{remote_dir}' on the "
            f"target — likely a permissions issue for this SSH user on that path: {e}"
        ) from e

    _run(client, f"chmod +x {shlex.quote(posixpath.join(remote_dir, 'server_audit.sh'))} "
                 f"{shlex.quote(posixpath.join(remote_dir, 'install_tools.sh'))}", timeout=15)


def upload_health_env(client: paramiko.SSHClient, remote_dir: str, content: str):
    sftp = client.open_sftp()
    try:
        remote_path = posixpath.join(remote_dir, "linux-health", "health.env")
        with sftp.file(remote_path, "w") as f:
            f.write(content)
    finally:
        sftp.close()


def test_connection(target: SSHTarget) -> CommandResult:
    """Lightweight connection checker — connects over SSH and runs a trivial
    command. Never uploads scripts or does tool detection, so it returns
    quickly even on slow links."""
    with ssh_connection(target) as client:
        return _run(client, "echo ok && hostname", timeout=15)


def check_tools(target: SSHTarget, remote_dir: str = None) -> CommandResult:
    remote_dir = remote_dir or settings.remote_workdir
    with ssh_connection(target) as client:
        upload_scripts(client, remote_dir)
        cmd = f"cd {shlex.quote(remote_dir)} && {_sudo_prefix(target.sudo_password)} ./server_audit.sh --check"
        return _run(client, cmd, timeout=60, sudo_password=target.sudo_password)


def install_tools(target: SSHTarget, tools: list[str], remote_dir: str = None) -> CommandResult:
    bad = set(tools) - ALLOWED_TOOLS
    if bad:
        raise RemoteExecError(f"Refusing to install unrecognized tool(s): {sorted(bad)}")
    if not tools:
        raise RemoteExecError("No tools specified")
    remote_dir = remote_dir or settings.remote_workdir
    only_arg = ",".join(sorted(set(tools)))  # fixed enum values only, comma-joined
    with ssh_connection(target) as client:
        upload_scripts(client, remote_dir)
        cmd = (
            f"cd {shlex.quote(remote_dir)} && "
            f"{_sudo_prefix(target.sudo_password)} ./install_tools.sh --only {shlex.quote(only_arg)} --yes"
        )
        return _run(
            client, cmd, timeout=settings.install_task_hard_timeout_seconds, sudo_password=target.sudo_password
        )


def run_audit(
    target: SSHTarget,
    web_targets: list[str] = (),
    full_scan: bool = False,
    skip_nmap: bool = False,
    skip_zap: bool = False,
    skip_lynis: bool = False,
    health_env_content: Optional[str] = None,
    remote_dir: str = None,
) -> tuple[CommandResult, str, str]:
    """Runs server_audit.sh, returns (result, remote_output_dir, timestamp_used).
    Caller is responsible for downloading the report afterwards via
    download_latest_report()."""
    remote_dir = remote_dir or settings.remote_workdir
    # Two distinct notions of this path, and they must NOT be conflated:
    #  - `output_dir_from_home`: relative to the SSH user's home, used by
    #    download_latest_report() afterwards, which opens a fresh
    #    session/SFTP connection that has no memory of any `cd`.
    #  - `output_dir_arg`: what we pass to server_audit.sh's `-o` flag,
    #    which must be relative to remote_dir itself, because the command
    #    below already does `cd {remote_dir} &&` before invoking the script.
    #    Passing the home-relative path here doubled it into
    #    remote_dir/remote_dir/audit_reports (root-owned, since the script
    #    runs under sudo) — a real bug that shipped briefly, now fixed.
    output_dir_from_home = posixpath.join(remote_dir, "audit_reports")
    output_dir_arg = "audit_reports"

    flags = ["-s", "-o", output_dir_arg]
    for url in web_targets:
        flags += ["-u", shlex.quote(url)]
    if full_scan:
        flags.append("--full-scan")
    if skip_nmap:
        flags.append("-n")
    if skip_zap:
        flags.append("-z")
    if skip_lynis:
        flags.append("-l")

    with ssh_connection(target, timeout=30) as client:
        upload_scripts(client, remote_dir)
        if health_env_content:
            upload_health_env(client, remote_dir, health_env_content)
            flags += ["--health-env", "linux-health/health.env"]

        cmd = (
            f"cd {shlex.quote(remote_dir)} && {_sudo_prefix(target.sudo_password)} ./server_audit.sh "
            + " ".join(flags)
        )
        result = _run(
            client, cmd, timeout=settings.audit_task_hard_timeout_seconds, sudo_password=target.sudo_password
        )
        return result, output_dir_from_home, flags


def download_latest_report(target: SSHTarget, remote_output_dir: str, local_dest_path: str) -> str:
    """Finds the most recent timestamped subfolder under remote_output_dir,
    downloads its security_audit_report_*.html to local_dest_path.
    Returns the remote run-log path (for a fuller log on failure).

    The audit script runs under sudo on the remote host, so all report files
    are root-owned.  The *primary* download path is SFTP (fast, streamed),
    which works when the SSH user can read the files.  A *fallback* uses SSH
    ``sudo cat`` + base64 to pipe the file through when permissions prevent
    a direct SFTP read.
    """
    with ssh_connection(target) as client:
        find_cmd = (
            f"ls -1dt {shlex.quote(remote_output_dir)}/*/ 2>/dev/null | head -n1"
        )
        latest = _run(client, find_cmd, timeout=15).stdout.strip()
        if not latest:
            raise RemoteExecError("No audit_reports subfolder found after run")

        remote_report: Optional[str] = None

        # --- primary path: SFTP (no sudo needed, fast) ---
        sftp = client.open_sftp()
        try:
            entries = sftp.listdir(latest)
            report_files = [
                e for e in entries
                if e.startswith("security_audit_report_") and e.endswith(".html")
            ]
            if report_files:
                remote_report = posixpath.join(latest, sorted(report_files)[-1])
                # Download now while we have the SFTP channel open
                os.makedirs(os.path.dirname(local_dest_path), exist_ok=True)
                sftp.get(remote_report, local_dest_path)
        except (IOError, OSError, paramiko.SSHException):
            # SFTP failed (likely permissions on sudo-created dirs).
            # Fall through to the SSH sudo fallback below.
            pass
        finally:
            sftp.close()

        # --- fallback: SSH sudo ls + sudo base64 ---
        if remote_report is None:
            # First, try sudo ls so the error message is informative
            ls_out = _run(
                client,
                f"{_sudo_prefix(target.sudo_password)} ls -la {shlex.quote(latest)} 2>/dev/null",
                timeout=15,
                sudo_password=target.sudo_password,
            )
            # Look for an HTML report file in the listing
            for line in ls_out.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 9:
                    fname = parts[-1]
                    if fname.startswith("security_audit_report_") and fname.endswith(".html"):
                        remote_report = posixpath.join(latest, fname)
                        break

            if remote_report is None:
                diag = (
                    f"sudo ls -la output:\n{ls_out.stdout[:2000]}{ls_out.stderr[:1000]}"
                )
                raise RemoteExecError(
                    f"No report HTML found in {latest}\n"
                    f"Directory contents:\n{diag}"
                )

            # Download via sudo base64 to avoid encoding issues
            cat_result = _run(
                client,
                f"{_sudo_prefix(target.sudo_password)} base64 {shlex.quote(remote_report)}",
                timeout=30,
                sudo_password=target.sudo_password,
            )
            try:
                raw = base64.b64decode(cat_result.stdout.strip())
            except Exception as _b64_err:
                raise RemoteExecError(
                    f"Found report {remote_report} but could not read it via sudo base64: {_b64_err}"
                ) from _b64_err

            os.makedirs(os.path.dirname(local_dest_path), exist_ok=True)
            with open(local_dest_path, "wb") as f:
                f.write(raw)

        return posixpath.join(latest, "audit_run.log")


def fetch_log_tail(target: SSHTarget, remote_log_path: str, lines: int = 200) -> str:
    try:
        with ssh_connection(target) as client:
            result = _run(client, f"tail -n {lines} {shlex.quote(remote_log_path)}", timeout=15)
            return result.stdout
    except Exception as e:  # noqa: BLE001
        return f"(could not fetch remote log: {e})"


# server_audit.sh's own log() calls print lines like:
#   [07:17:30] ═══ Phase 2: Infrastructure Audit (Lynis) ═══
# (the leading [HH:MM:SS] is wrapped in ANSI color codes; the phase text
# itself is not, so this matches regardless of that wrapping.)
_PHASE_LINE_RE = re.compile(r"Phase\s+\d+:\s*([^═\n]+?)\s*═")


def poll_audit_phase(target: SSHTarget, remote_dir: str, run_id: str, stop_event) -> None:
    """Runs on its own SSH connection, in parallel with the main run_audit()
    call, for the lifetime of one audit run. Every few seconds it greps the
    *run's own* audit_run.log for the most recent '═══ Phase N: ... ═══'
    line — text server_audit.sh already writes as it works through its own
    fixed, real phase sequence — and records that on the AuditRun row so the
    UI can show genuine progress instead of a guess. This function only ever
    reads a log file; it has no ability to change anything on the target.

    Best-effort by design: any failure here (a slow network blip, the log
    not existing yet, etc.) is swallowed rather than raised, because a
    progress-reporting side channel must never be able to fail the actual
    audit run it's reporting on.
    """
    from ..database import SessionLocal
    from .. import models
    import logging

    logger = logging.getLogger("app.phase_poller")
    output_dir = posixpath.join(remote_dir, "audit_reports")
    log_path: Optional[str] = None
    last_phase: Optional[str] = None

    # Outer loop: reconnect on any connection-level failure instead of
    # giving up for the rest of the run. Without this, a single transient
    # failure to open this side-channel connection (e.g. a timing hiccup
    # opening it right alongside the main audit's own connection) would
    # silently end all progress reporting for the entire run with nothing
    # in the logs to explain why.
    while not stop_event.is_set():
        try:
            with ssh_connection(target, timeout=15) as client:
                while not stop_event.is_set():
                    try:
                        if log_path is None:
                            latest = _run(
                                client,
                                f"ls -1dt {shlex.quote(output_dir)}/*/ 2>/dev/null | head -n1",
                                timeout=10,
                            ).stdout.strip()
                            if latest:
                                log_path = posixpath.join(latest, "audit_run.log")
                                logger.info("phase poller for run %s found log at %s", run_id, log_path)

                        if log_path:
                            out = _run(
                                client,
                                f"grep 'Phase' {shlex.quote(log_path)} 2>/dev/null | tail -n1",
                                timeout=10,
                            ).stdout
                            m = _PHASE_LINE_RE.search(out)
                            if m:
                                phase = m.group(1).strip()
                                if phase != last_phase:
                                    last_phase = phase
                                    logger.info("run %s now in phase: %s", run_id, phase)
                                    db = SessionLocal()
                                    try:
                                        run = db.query(models.AuditRun).get(run_id)
                                        if run and run.status == models.RunStatus.running:
                                            summary = dict(run.summary or {})
                                            summary["current_phase"] = phase
                                            run.summary = summary
                                            db.commit()
                                        elif not run:
                                            logger.warning("phase poller: run %s no longer exists", run_id)
                                    finally:
                                        db.close()
                    except Exception as e:  # noqa: BLE001
                        logger.warning("phase poller: one poll failed for run %s: %s", run_id, e)
                    stop_event.wait(4)
        except Exception as e:  # noqa: BLE001
            if stop_event.is_set():
                break
            logger.warning(
                "phase poller: connection failed for run %s, retrying in 10s: %s", run_id, e
            )
            stop_event.wait(10)
