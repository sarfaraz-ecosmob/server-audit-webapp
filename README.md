# Server Audit SaaS

Multi-project, multi-server web dashboard on top of your existing
`server_audit.sh` / `install_tools.sh` / `gen_report.py` toolchain. See
[`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full design writeup — start
there for the "why", this file is just the "how to run it".

```
server-audit-saas/
├── ARCHITECTURE.md          <- read this first
├── docker-compose.yml
├── .env.example
├── docker/nginx/nginx.conf   <- single entry point; routes /api to backend, / to frontend
├── backend/                 FastAPI + Celery + paramiko
│   ├── scripts/              bundled copies of your 3 scripts (verbatim)
│   └── app/
│       ├── services/ssh_executor.py   <- the ONLY code that SSHes anywhere
│       ├── services/report_parser.py  <- scrapes summary numbers from the HTML report
│       ├── tasks.py                    <- Celery jobs (install / audit)
│       └── routers/                    <- REST API, all under /api
└── frontend/                 Next.js 15 / React 19
    └── src/app/               projects → servers → dashboard
```

## Run it

```bash
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(48))"   # -> JWT_SECRET
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # -> SECRET_ENCRYPTION_KEY
# paste both into .env

docker compose up --build
```

- App: **http://localhost/** (through nginx on port 80 — this is the URL to use)
- API docs (Swagger): http://localhost:8000/docs
- Frontend/backend are also reachable directly on :3000/:8000 for debugging, but nginx on :80 is the intended entry point

### Accessing it from a remote server

This works unmodified from any host — a server's public IP, a domain,
whatever — with **no rebuild and no config to change**. The frontend calls
the API via a relative `/api` path, and nginx (port 80) proxies `/api/*` to
the backend and everything else to the frontend, all on one origin. Since
the browser only ever talks to one origin, CORS is never actually invoked
— there's no cross-origin request happening in the first place. Just point
a browser at `http://<your-server-ip>/` (or a domain once you've pointed
DNS at it) and register/sign in exactly as you would locally.

This ships as plain HTTP. For anything beyond local testing, put a TLS
terminator in front of port 80 — a managed load balancer, Caddy, or
certbot + nginx — since login credentials and SSH passwords/keys otherwise
travel in the clear between the browser and this server.

Register an account, create a project, add a server with its SSH
credentials (password or private key), hit **Test connection** to confirm
reachability and see what's already installed, optionally **Install
tools** (only `lynis`/`nmap`/`rkhunter`/`zap-docker`, nothing else, ever),
then **Run audit**. The report renders inline once the run completes and is
downloadable as the same self-contained HTML file `gen_report.py` produces.

## Before pointing this at production servers

1. Generate a dedicated SSH key for the app rather than reusing personal
   credentials, and prefer key auth over password auth.
2. Review `backend/app/services/ssh_executor.py` — it's short and it's the
   entire remote-command surface of the app; confirm for yourself it never
   does more than run the two whitelisted scripts.
3. Set real, non-default `JWT_SECRET` / `SECRET_ENCRYPTION_KEY` (the
   compose file refuses to start without them, on purpose).
4. Put the backend/worker containers on a network segment that only has SSH
   egress to hosts you intend to audit.
5. `sudo -S` (password piped over stdin, never as a CLI arg or in logs) is
   used for the remote install/audit commands whenever a sudo password is
   available — either the explicit one you set on the server, or the SSH
   login password itself when auth is password-based. For key-based login
   with no sudo password set, it falls back to `sudo -n` (non-interactive),
   which needs NOPASSWD sudo configured on the target instead.
6. Scripts get copied to `~/security-audit-tooling` on each target (relative
   to whatever SSH user you configured — no `/opt` or other root-owned path
   involved), so any SSH user with a normal home directory works out of the
   box with no extra filesystem permissions to set up. If **Test connection**
   ever fails, the error message now tells you which stage failed —
   SSH auth vs. writing files to that directory vs. running the script —
   rather than a generic "could not connect".
7. If a worker container is ever killed mid-run (a restart during a deploy,
   an OOM kill, `docker compose down`), the run it was working on is
   automatically marked failed the moment a new worker process starts back
   up — see `_reconcile_orphaned_runs` in `celery_app.py`. Otherwise that
   row would stay stuck at "running" forever with nothing left to ever
   update it, which is exactly the failure mode you'd see as an audit stuck
   at some enormous elapsed time that never completes.
8. Audit/install runs also have a real Celery-enforced wall-clock limit now
   (`AUDIT_TASK_HARD_TIMEOUT_SECONDS`, default 2 hours; `INSTALL_TASK_HARD_TIMEOUT_SECONDS`,
   default 15 min) — the per-command socket timeouts inside `ssh_executor.py`
   only fire on total silence, so a script that's stuck but still printing
   occasional output wouldn't have tripped those alone.
