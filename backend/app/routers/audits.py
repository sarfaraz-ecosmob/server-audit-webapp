import os

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, PlainTextResponse
from sqlalchemy.orm import Session

from .. import models, schemas, auth
from ..database import get_db

router = APIRouter(prefix="/audit-runs", tags=["audit-runs"])


def _get_owned_run(run_id: str, db: Session, user: models.User) -> models.AuditRun:
    run = db.query(models.AuditRun).filter(models.AuditRun.id == run_id).first()
    if not run or run.server.project.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Run not found")
    return run


@router.get("/{run_id}", response_model=schemas.AuditRunOut)
def get_run(run_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    return _get_owned_run(run_id, db, user)


@router.get("/{run_id}/log", response_class=PlainTextResponse)
def get_run_log(run_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    run = _get_owned_run(run_id, db, user)
    return run.log_tail or ""


@router.get("/{run_id}/report")
def get_run_report(run_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    run = _get_owned_run(run_id, db, user)
    if not run.report_path or not os.path.exists(run.report_path):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not available for this run")
    return FileResponse(
        run.report_path,
        media_type="text/html",
        filename=f"security_audit_report_{run.server.name}_{run.id}.html",
    )
