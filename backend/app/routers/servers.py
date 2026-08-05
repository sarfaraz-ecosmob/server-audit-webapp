from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import models, schemas, auth, crypto, tasks
from ..database import get_db
from ..services import ssh_executor
from .projects import _get_owned_project

router = APIRouter(tags=["servers"])


def _get_owned_server(server_id: str, db: Session, user: models.User) -> models.Server:
    server = db.query(models.Server).filter(models.Server.id == server_id).first()
    if not server or server.project.owner_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    return server


@router.post(
    "/projects/{project_id}/servers",
    response_model=schemas.ServerOut,
    status_code=status.HTTP_201_CREATED,
)
def add_server(
    project_id: str,
    payload: schemas.ServerCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    project = _get_owned_project(project_id, db, user)

    if payload.auth_type == "password":
        if not payload.password:
            raise HTTPException(422, "password is required when auth_type=password")
        secret_encrypted = crypto.encrypt_password(payload.password)
    else:
        if not payload.private_key:
            raise HTTPException(422, "private_key is required when auth_type=private_key")
        secret_encrypted = crypto.encrypt_private_key(
            payload.private_key, payload.private_key_passphrase
        )

    health_env_encrypted = (
        crypto.encrypt_text(payload.health_env_content) if payload.health_env_content else None
    )
    sudo_password_encrypted = (
        crypto.encrypt_password(payload.sudo_password) if payload.sudo_password else None
    )

    server = models.Server(
        project_id=project.id,
        name=payload.name,
        host=payload.host,
        port=payload.port,
        username=payload.username,
        auth_type=payload.auth_type,
        secret_encrypted=secret_encrypted,
        sudo_password_encrypted=sudo_password_encrypted,
        web_targets=payload.web_targets,
        health_env_encrypted=health_env_encrypted,
        installed_tools={},
    )
    db.add(server)
    db.commit()
    db.refresh(server)
    return server


@router.get("/servers/{server_id}", response_model=schemas.ServerOut)
def get_server(server_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    return _get_owned_server(server_id, db, user)


@router.patch("/servers/{server_id}", response_model=schemas.ServerOut)
def update_server(
    server_id: str,
    payload: schemas.ServerUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    server = _get_owned_server(server_id, db, user)

    if payload.name is not None:
        server.name = payload.name
    if payload.host is not None:
        server.host = payload.host
    if payload.port is not None:
        server.port = payload.port
    if payload.username is not None:
        server.username = payload.username
    if payload.web_targets is not None:
        server.web_targets = payload.web_targets
    if payload.health_env_content is not None:
        server.health_env_encrypted = (
            crypto.encrypt_text(payload.health_env_content) if payload.health_env_content else None
        )
    if payload.sudo_password:
        server.sudo_password_encrypted = crypto.encrypt_password(payload.sudo_password)
    elif payload.clear_sudo_password:
        server.sudo_password_encrypted = None

    # Credentials: only touched if the caller actually sent new ones.
    # auth_type can switch (e.g. password -> private_key) but must come
    # with the matching secret in the same request.
    new_auth_type = payload.auth_type or server.auth_type
    if payload.password is not None:
        if new_auth_type != "password":
            raise HTTPException(422, "password provided but auth_type is not 'password'")
        server.auth_type = models.AuthType.password
        server.secret_encrypted = crypto.encrypt_password(payload.password)
    elif payload.private_key is not None:
        if new_auth_type != "private_key":
            raise HTTPException(422, "private_key provided but auth_type is not 'private_key'")
        server.auth_type = models.AuthType.private_key
        server.secret_encrypted = crypto.encrypt_private_key(
            payload.private_key, payload.private_key_passphrase
        )
    elif payload.auth_type is not None and payload.auth_type != server.auth_type:
        raise HTTPException(
            422, "Changing auth_type requires providing the matching new credential"
        )

    db.commit()
    db.refresh(server)
    return server


@router.delete("/servers/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_server(server_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    server = _get_owned_server(server_id, db, user)
    db.delete(server)
    db.commit()


@router.post("/servers/{server_id}/test-connection")
def test_connection(server_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    """Synchronous, lightweight: simply tests SSH connectivity by connecting
    and running a trivial command. No scripts are uploaded, no tools are
    detected. Returns within seconds unless the network is genuinely slow."""
    server = _get_owned_server(server_id, db, user)
    target = tasks._build_target(server)
    try:
        result = ssh_executor.test_connection(target)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e))

    return {"exit_code": result.exit_code, "output": result.stdout[-2000:], "duration_seconds": round(result.duration_seconds, 2)}


@router.post(
    "/servers/{server_id}/install-tools",
    response_model=schemas.AuditRunOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def install_tools(
    server_id: str,
    payload: schemas.InstallToolsRequest,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    server = _get_owned_server(server_id, db, user)
    if not payload.tools:
        raise HTTPException(422, "Select at least one tool")

    run = models.AuditRun(
        server_id=server.id,
        run_type=models.RunType.install_tools,
        status=models.RunStatus.queued,
        requested_tools=payload.tools,
        flags=[],
        triggered_by_user_id=user.id,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    tasks.install_tools_task.delay(run.id)
    return run


@router.post(
    "/servers/{server_id}/audit-runs",
    response_model=schemas.AuditRunOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def start_audit(
    server_id: str,
    payload: schemas.AuditRunRequest,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    server = _get_owned_server(server_id, db, user)

    flags: list[str] = []
    web_targets = payload.web_targets if payload.web_targets is not None else server.web_targets
    for url in web_targets or []:
        flags += ["-u", url]
    if payload.full_scan:
        flags.append("--full-scan")
    if payload.skip_nmap:
        flags.append("-n")
    if payload.skip_zap:
        flags.append("-z")
    if payload.skip_lynis:
        flags.append("-l")

    run = models.AuditRun(
        server_id=server.id,
        run_type=models.RunType.audit,
        status=models.RunStatus.queued,
        requested_tools=[],
        flags=flags,
        triggered_by_user_id=user.id,
    )
    db.add(run)
    db.commit()
    db.refresh(run)

    tasks.run_audit_task.delay(run.id)
    return run


@router.get("/servers/{server_id}/audit-runs", response_model=list[schemas.AuditRunOut])
def list_runs(server_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    server = _get_owned_server(server_id, db, user)
    return server.runs
