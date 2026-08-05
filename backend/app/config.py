import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = os.environ.get(
        "DATABASE_URL", "postgresql://audit:audit@postgres:5432/audit_saas"
    )
    redis_url: str = os.environ.get("REDIS_URL", "redis://redis:6379/0")

    # JWT
    jwt_secret: str = os.environ["JWT_SECRET"]  # required, no default on purpose
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 24

    # Fernet key for encrypting SSH credentials at rest. Generate with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    secret_encryption_key: str = os.environ["SECRET_ENCRYPTION_KEY"]  # required

    # Where uploaded/downloaded audit reports are cached locally by the backend
    report_storage_dir: str = os.environ.get("REPORT_STORAGE_DIR", "/data/reports")

    # Absolute path (inside backend container) to the bundled scripts that get
    # copied to remote servers. Never user-editable.
    scripts_dir: str = os.environ.get(
        "SCRIPTS_DIR", os.path.join(os.path.dirname(__file__), "..", "scripts")
    )

    # Where scripts/reports live on the AUDITED server. Deliberately relative
    # (no leading slash): paramiko's exec_command and SFTP both default to
    # the SSH user's home directory, so this works for any user without
    # needing write access to a shared system path like /opt. Override via
    # env var only if you specifically want a shared absolute path AND have
    # already chown'd/chmod'd it for every SSH user you'll add.
    remote_workdir: str = os.environ.get("REMOTE_WORKDIR", "security-audit-tooling")

    # Comma-separated list of allowed browser origins for CORS, e.g.
    # "https://audit.example.com,https://audit-staging.example.com".
    # Defaults to "*" (any origin). Even when "*" is set, the middleware now
    # uses allow_origin_regex=".*" with allow_credentials=True so that the
    # exact request origin is echoed back — this makes credentialed
    # cross-origin requests (Authorization header) work reliably in all
    # browsers, unlike a bare "*" which browsers refuse once credentials are
    # involved. Safe to keep permissive: auth is a Bearer token, never a
    # cookie, so there is zero CSRF/cookie-theft risk from any origin.
    cors_allowed_origins: str = os.environ.get("CORS_ALLOWED_ORIGINS", "*")

    # Optional regex pattern to match allowed origins. When set, origins that
    # match this regex are allowed even if not in cors_allowed_origins list.
    # Defaults to ".*" (match all) when cors_allowed_origins contains "*".
    cors_origin_regex: str = os.environ.get("CORS_ORIGIN_REGEX", "")

    # Hard ceiling for a full audit run before Celery kills the task,
    # on top of the script's own internal per-phase timeouts.
    audit_task_hard_timeout_seconds: int = 2 * 60 * 60  # 2 hours
    install_task_hard_timeout_seconds: int = 15 * 60


settings = Settings()
