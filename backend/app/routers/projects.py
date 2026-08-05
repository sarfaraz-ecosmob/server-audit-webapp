from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import models, schemas, auth
from ..database import get_db

router = APIRouter(prefix="/projects", tags=["projects"])


def _get_owned_project(project_id: str, db: Session, user: models.User) -> models.Project:
    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project or project.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return project


@router.post("", response_model=schemas.ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: schemas.ProjectCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    project = models.Project(owner_id=user.id, name=payload.name, description=payload.description)
    db.add(project)
    db.commit()
    db.refresh(project)
    out = schemas.ProjectOut.model_validate(project)
    out.server_count = 0
    return out


@router.get("", response_model=list[schemas.ProjectOut])
def list_projects(db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    projects = db.query(models.Project).filter(models.Project.owner_id == user.id).all()
    results = []
    for p in projects:
        out = schemas.ProjectOut.model_validate(p)
        out.server_count = len(p.servers)
        results.append(out)
    return results


@router.get("/{project_id}", response_model=schemas.ProjectOut)
def get_project(
    project_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)
):
    project = _get_owned_project(project_id, db, user)
    out = schemas.ProjectOut.model_validate(project)
    out.server_count = len(project.servers)
    return out


@router.get("/{project_id}/servers", response_model=list[schemas.ServerOut])
def list_servers(
    project_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)
):
    project = _get_owned_project(project_id, db, user)
    return project.servers


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)
):
    project = _get_owned_project(project_id, db, user)
    db.delete(project)
    db.commit()
