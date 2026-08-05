import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, Integer, DateTime, ForeignKey, Text, Enum, JSON,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .database import Base


def gen_uuid():
    return str(uuid.uuid4())


class AuthType(str, enum.Enum):
    password = "password"
    private_key = "private_key"


class RunType(str, enum.Enum):
    install_tools = "install_tools"
    audit = "audit"
    test_connection = "test_connection"


class RunStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    projects = relationship("Project", back_populates="owner")


class Project(Base):
    __tablename__ = "projects"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    owner_id = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="projects")
    servers = relationship("Server", back_populates="project", cascade="all, delete-orphan")


class Server(Base):
    __tablename__ = "servers"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    project_id = Column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)

    name = Column(String, nullable=False)
    host = Column(String, nullable=False)
    port = Column(Integer, default=22)
    username = Column(String, nullable=False)

    auth_type = Column(Enum(AuthType), nullable=False)
    # Fernet-encrypted blob: password string, or "<private_key>\n---PASSPHRASE---\n<passphrase>"
    secret_encrypted = Column(Text, nullable=False)
    # Optional, independent of the SSH login credential above. Used to
    # authenticate `sudo` on the target when installing tools/running the
    # audit. If null and auth_type is 'password', the SSH password is reused
    # for sudo. If null and auth_type is 'private_key', sudo runs as
    # non-interactive (`sudo -n`), which requires NOPASSWD sudo already
    # configured on the target.
    sudo_password_encrypted = Column(Text, nullable=True)

    web_targets = Column(JSON, default=list)  # list[str] of URLs for -u flags
    health_env_encrypted = Column(Text, nullable=True)

    installed_tools = Column(JSON, default=dict)  # last known --check result
    last_run_id = Column(UUID(as_uuid=False), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    project = relationship("Project", back_populates="servers")
    runs = relationship(
        "AuditRun", back_populates="server", cascade="all, delete-orphan",
        order_by="desc(AuditRun.started_at)",
    )

    @property
    def has_sudo_password(self) -> bool:
        return bool(self.sudo_password_encrypted)


class AuditRun(Base):
    __tablename__ = "audit_runs"
    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    server_id = Column(UUID(as_uuid=False), ForeignKey("servers.id"), nullable=False)

    run_type = Column(Enum(RunType), nullable=False)
    status = Column(Enum(RunStatus), default=RunStatus.queued, nullable=False)

    requested_tools = Column(JSON, default=list)   # for install_tools runs
    flags = Column(JSON, default=list)              # exact server_audit.sh flags used

    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)

    log_tail = Column(Text, default="")
    report_path = Column(String, nullable=True)
    summary = Column(JSON, nullable=True)

    triggered_by_user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)

    server = relationship("Server", back_populates="runs")
