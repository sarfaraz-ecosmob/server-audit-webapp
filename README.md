# Server Audit SaaS

A self-hosted web dashboard for running automated Linux security audits across multiple servers — from the browser, with no agents, no cloud dependency, and no manual SSH sessions.

## What is this?

Server Audit SaaS is a multi-project, multi-server web application that wraps your existing `server_audit.sh` / `install_tools.sh` / `gen_report.py` shell toolchain in a proper UI. Instead of SSH-ing into each box, running scripts by hand, and collecting HTML reports manually, you manage everything from a single dashboard.

**What it does:**

- **Organize servers into projects** — group your infrastructure logically (e.g. "Production", "Staging", "Client A"), each with its own set of servers and audit history.
- **Store SSH credentials securely** — password or private key, encrypted at rest with Fernet (AES-128-CBC + HMAC). Credentials are decrypted only in worker memory during an active SSH session and never written to disk or logs.
- **Test connectivity before committing** — "Test connection" SSHes in, checks which audit tools are already installed, and reports exactly which stage failed (auth / file write / script execution) if anything goes wrong.
- **Install audit tools on demand** — optionally installs `lynis`, `nmap`, `rkhunter`, and/or `zap-docker` on the target server via `install_tools.sh`. Nothing else is ever installed. The allowed tool list is a fixed enum on the backend — there is no free-text command path.
- **Run security audits remotely** — queues an audit job (Celery + Redis), SSHes into the target, uploads the scripts, runs `server_audit.sh`, downloads the resulting HTML report over SFTP, and marks the run complete. Audits can run 15–45+ minutes; they run in the background without blocking your browser or other servers' audits.
- **Browse audit history** — every run is stored with its status, timestamps, log tail, and the full HTML report. You can go back to any previous audit for any server.
- **View reports inline** — the HTML report produced by `gen_report.py` is rendered directly in an iframe inside the dashboard. No re-parsing, no data loss — you see the exact same report the script produces.
- **Download reports** — each report is downloadable as the original self-contained HTML file.

**What it does NOT do:**

- It does not install anything beyond the four whitelisted tools. The backend enforces this structurally — there is no "run arbitrary command" API surface.
- It does not require any agent or daemon on the target servers. The only footprint is the scripts copied to `~/security-audit-tooling/` and the reports written to `~/audit_reports/`.
- It does not phone home or require internet access (beyond whatever the audit tools themselves need, e.g. Lynis updates).

**Tech stack:**

| Layer | Technology |
|---|---|
| Frontend | Next.js 15 / React 19 / Tailwind CSS |
| Backend API | FastAPI (Python) |
| Background jobs | Celery + Redis |
| Remote execution | paramiko (SSH/SFTP) |
| Database | PostgreSQL |
| Reverse proxy | nginx (single entry point on port 80) |
| Deployment | Docker Compose |

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full design writeup — it covers the security model, data model, API surface, and implementation decisions in detail.

---

## Project structure

```
server-audit-saas/
├── ARCHITECTURE.md          <- full design writeup; read this before modifying anything
├── docker-compose.yml
├── .env.example
├── docker/nginx/nginx.conf   <- single entry point; routes /api to backend, / to frontend
├── backend/                  FastAPI + Celery + paramiko
│   ├── scripts/              bundled copies of your 3 scripts (verbatim)
│   └── app/
│       ├── services/ssh_executor.py   <- the ONLY code that SSHes anywhere
│       ├── services/report_parser.py  <- scrapes summary numbers from the HTML report
│       ├── tasks.py                    <- Celery jobs (install / audit)
│       └── routers/                    <- REST API, all under /api
└── frontend/                 Next.js 15 / React 19
    └── src/app/               projects → servers → dashboard
```

---

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

### Typical workflow

1. Register an account and create a **Project** (e.g. "Production VoIP").
2. Add a **Server** — host/IP, SSH port, username, and either a password or a private key.
3. Hit **Test connection** to confirm reachability and see what's already installed.
4. Optionally click **Install tools** and pick which of `lynis` / `nmap` / `rkhunter` / `zap-docker` to install — you'll see a preview of the exact command before it runs.
5. Click **Run audit**. The job queues immediately; the dashboard polls for status and unlocks the report viewer once it completes.
6. Browse the inline report or download it as a standalone HTML file. Previous runs are kept in the history table.

### Accessing it from a remote server

This works unmodified from any host — a server's public IP, a domain, whatever — with **no rebuild and no config to change**. The frontend calls the API via a relative `/api` path, and nginx (port 80) proxies `/api/*` to the backend and everything else to the frontend, all on one origin. Since the browser only ever talks to one origin, CORS is never actually invoked — there's no cross-origin request happening in the first place. Just point a browser at `http://<your-server-ip>/` (or a domain once you've pointed DNS at it) and register/sign in exactly as you would locally.

This ships as plain HTTP. For anything beyond local testing, put a TLS terminator in front of port 80 — a managed load balancer, Caddy, or certbot + nginx — since login credentials and SSH passwords/keys otherwise travel in the clear between the browser and this server.

---

## Before pointing this at production servers

1. Generate a dedicated SSH key for the app rather than reusing personal credentials, and prefer key auth over password auth.
2. Review `backend/app/services/ssh_executor.py` — it's short and it's the entire remote-command surface of the app; confirm for yourself it never does more than run the two whitelisted scripts.
3. Set real, non-default `JWT_SECRET` / `SECRET_ENCRYPTION_KEY` (the compose file refuses to start without them, on purpose).
4. Put the backend/worker containers on a network segment that only has SSH egress to hosts you intend to audit.
5. `sudo -S` (password piped over stdin, never as a CLI arg or in logs) is used for the remote install/audit commands whenever a sudo password is available — either the explicit one you set on the server, or the SSH login password itself when auth is password-based. For key-based login with no sudo password set, it falls back to `sudo -n` (non-interactive), which needs NOPASSWD sudo configured on the target instead.
6. Scripts get copied to `~/security-audit-tooling` on each target (relative to whatever SSH user you configured — no `/opt` or other root-owned path involved), so any SSH user with a normal home directory works out of the box with no extra filesystem permissions to set up. If **Test connection** ever fails, the error message tells you which stage failed — SSH auth vs. writing files to that directory vs. running the script — rather than a generic "could not connect".
7. If a worker container is ever killed mid-run (a restart during a deploy, an OOM kill, `docker compose down`), the run it was working on is automatically marked failed the moment a new worker process starts back up — see `_reconcile_orphaned_runs` in `celery_app.py`. Otherwise that row would stay stuck at "running" forever with nothing left to ever update it.
8. Audit/install runs have a Celery-enforced wall-clock limit (`AUDIT_TASK_HARD_TIMEOUT_SECONDS`, default 2 hours; `INSTALL_TASK_HARD_TIMEOUT_SECONDS`, default 15 min) — the per-command socket timeouts inside `ssh_executor.py` only fire on total silence, so a script that's stuck but still printing occasional output wouldn't have tripped those alone.
