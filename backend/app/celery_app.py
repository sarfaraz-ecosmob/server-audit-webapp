from celery import Celery

from .config import settings

celery_app = Celery(
    "server_audit_saas",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    # Never persist task args/results containing decrypted credentials.
    # We only ever pass IDs into tasks (see tasks.py) and re-fetch/decrypt
    # inside the worker, so nothing sensitive reaches the result backend.
    result_expires=3600,
)

# The worker process is started as `celery -A app.celery_app.celery_app worker`,
# which only imports this module — task functions defined in app/tasks.py would
# never get registered with the worker without this import, and every task
# would be silently dropped with "Received unregistered task". Importing here
# (after `celery_app` is already assigned above) is safe despite tasks.py doing
# `from .celery_app import celery_app` — Python finds this partially-initialized
# module in sys.modules and the attribute is already set.
from . import tasks  # noqa: E402,F401

from celery.signals import worker_ready  # noqa: E402


@worker_ready.connect
def _reconcile_orphaned_runs(**kwargs):
    """Runs once, right after a worker process comes up.

    A fresh worker process has zero memory of any task a *previous* worker
    process might have been mid-way through. If that previous process was
    killed — a container restart during a deploy, an OOM kill, `docker
    compose down`, anything — whatever AuditRun row it was working on is
    left at status='running' forever: the code that would normally flip it
    to completed/failed lived inside that now-dead process, so nothing will
    ever touch that row again. The UI would show it as "running" — with an
    ever-climbing elapsed timer — indefinitely, with no way to tell that
    from a real long scan.

    Since this fires at worker startup, ANY row still marked running/queued
    at this exact moment cannot legitimately be in-flight on this fresh
    worker (it hasn't picked up a single task yet), so it's safe to mark
    these as failed, with an explanation, rather than leave them stuck.
    """
    from .database import SessionLocal
    from . import models
    from datetime import datetime

    db = SessionLocal()
    try:
        orphaned = (
            db.query(models.AuditRun)
            .filter(models.AuditRun.status.in_([models.RunStatus.running, models.RunStatus.queued]))
            .all()
        )
        for run in orphaned:
            run.status = models.RunStatus.failed
            run.finished_at = datetime.utcnow()
            run.log_tail = (
                (run.log_tail or "")
                + "\n\n[Marked failed automatically] This run was still "
                  "queued/running when a fresh worker process started with "
                  "no memory of it — the previous worker was very likely "
                  "restarted or crashed mid-task. Please rerun."
            )[-6000:]
        if orphaned:
            db.commit()
    finally:
        db.close()
