from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import Base, engine
from . import models  # noqa: F401  (ensures models are registered before create_all)
from .routers import auth as auth_router, projects, servers, audits

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Server Audit SaaS API", version="0.1.0")

# ── CORS configuration ───────────────────────────────────────────────
# Strategy (see config.py for full rationale):
#   * By default (WILDCARD): use allow_origin_regex=".*" so that the
#     exact request origin is echoed in Access-Control-Allow-Origin.
#     This allows credentialed cross-origin requests (Bearer token via
#     the Authorization header) to work in ALL browsers, which a bare
#     "*" origin would silently fail for once the browser sees any
#     credential-related header.
#   * Specific origins: use allow_origins with allow_credentials=True
#     so that credentialed cross-origin requests are explicitly allowed
#     from those origins only.
#   * Regardless of deployment (behind nginx or direct), the middleware
#     always returns the correct CORS headers for both simple requests
#     and preflight OPTIONS.
_origins = [o.strip() for o in settings.cors_allowed_origins.split(",") if o.strip()]
_is_wildcard = "*" in _origins
_custom_regex = settings.cors_origin_regex.strip() or None

cors_kwargs = {
    "allow_credentials": True,
    "allow_methods": ["*"],
    "allow_headers": ["*"],
}

if _is_wildcard or _custom_regex:
    # Use a regex so the exact origin is echoed back (enables credentials).
    cors_kwargs["allow_origin_regex"] = _custom_regex or ".*"
else:
    cors_kwargs["allow_origins"] = _origins

app.add_middleware(CORSMiddleware, **cors_kwargs)

# Every real route lives under /api. This is what lets the frontend call a
# relative "/api/..." path and never need to know its own public IP/domain —
# nginx proxies "/api/*" straight through to this service, "/*" to the
# frontend, both on one origin. See docker/nginx/nginx.conf.
app.include_router(auth_router.router, prefix="/api")
app.include_router(projects.router, prefix="/api")
app.include_router(servers.router, prefix="/api")
app.include_router(audits.router, prefix="/api")


@app.get("/health")
def health():
    return {"status": "ok"}
