from datetime import datetime
from typing import Optional, List, Literal

from pydantic import BaseModel, EmailStr, Field

ToolName = Literal["lynis", "nmap", "rkhunter", "zap-docker", "trivy", "jq"]


# ---- Auth ----
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---- Projects ----
class ProjectCreate(BaseModel):
    name: str
    description: str = ""


class ProjectOut(BaseModel):
    id: str
    name: str
    description: str
    created_at: datetime
    server_count: int = 0

    class Config:
        from_attributes = True


# ---- Servers ----
class ServerCreate(BaseModel):
    name: str
    host: str
    port: int = 22
    username: str
    auth_type: Literal["password", "private_key"]
    # Exactly one of these must be provided, matching auth_type
    password: Optional[str] = None
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    # Optional. If omitted and auth_type='password', the SSH password above
    # is reused for `sudo` on the target. If omitted and auth_type is
    # 'private_key', sudo runs non-interactively and requires NOPASSWD sudo
    # already configured on the target.
    sudo_password: Optional[str] = None
    web_targets: List[str] = []
    health_env_content: Optional[str] = None  # raw contents of health.env, if provided


class ServerUpdate(BaseModel):
    """All fields optional — only what's provided gets changed.
    Credential fields (password/private_key/sudo_password) are only
    re-encrypted and replaced if explicitly sent; omitting them keeps the
    existing secret."""
    name: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    auth_type: Optional[Literal["password", "private_key"]] = None
    password: Optional[str] = None
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    sudo_password: Optional[str] = None
    clear_sudo_password: bool = False  # explicit opt-in to go back to "reuse SSH password / sudo -n"
    web_targets: Optional[List[str]] = None
    health_env_content: Optional[str] = None


class ServerOut(BaseModel):
    id: str
    name: str
    host: str
    port: int
    username: str
    auth_type: str
    has_sudo_password: bool = False
    web_targets: List[str]
    installed_tools: dict
    last_run_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


# ---- Runs ----
class InstallToolsRequest(BaseModel):
    tools: List[ToolName]


class AuditRunRequest(BaseModel):
    web_targets: Optional[List[str]] = None   # override server defaults for this run
    full_scan: bool = False                     # opt-in aggressive nmap
    skip_nmap: bool = False
    skip_zap: bool = False
    skip_lynis: bool = False
    use_health_env: bool = True


class AuditRunOut(BaseModel):
    id: str
    server_id: str
    run_type: str
    status: str
    requested_tools: list
    flags: list
    started_at: datetime
    finished_at: Optional[datetime] = None
    log_tail: str
    report_path: Optional[str] = None
    summary: Optional[dict] = None

    class Config:
        from_attributes = True
