# Server Audit SaaS — Architecture

Turns your existing `server_audit.sh` / `install_tools.sh` / `gen_report.py`
toolchain into a multi-project, multi-server web dashboard: add servers via
SSH credentials, install only the approved tools, run the audit, and browse
history — all from the browser, nothing installed on servers except what
`install_tools.sh` already allows.

## 1. Core constraint (read this first)

> "No other package should be installed on the server other than what is
> mentioned in install_tools.sh"

The backend enforces this structurally, not just by convention:

- The SSH executor has exactly **two** allowed remote commands:
  `install_tools.sh --only <subset of lynis,nmap,rkhunter,zap-docker> --yes`
  and `server_audit.sh <flags>`. There is no general "run arbitrary command"
  code path exposed to the API or the frontend.
- `--only` is always populated from a **fixed enum** on the backend
  (`ToolName = lynis | nmap | rkhunter | zap-docker`), never from a free-text
  field the user can edit — so nothing else can be smuggled into the command.
- `install_tools.sh` is copied to the server verbatim (checksummed) from the
  bundled copy in `backend/scripts/` — the app never generates or edits it.
- No config files are written on the target beyond what the scripts
  themselves already write to `audit_reports/` and `tmp/`.

## 2. High-level flow

```
Project ──has many──> Server (SSH creds) ──has many──> AuditRun (one per execution)
```

1. User creates a **Project** (e.g. "Ecosmob Production VoIP").
2. User adds a **Server** to the project: host/IP, SSH port, username, and
   either a password or a private key (both encrypted at rest, see §4).
3. On "Install Tools" (first-time setup, optional, explicit — mirrors the
   script's own philosophy): user picks a subset of
   `lynis / nmap / rkhunter / zap-docker` from checkboxes. Backend SSHes in,
   uploads `install_tools.sh`, runs it with `--only <picked> --yes`, streams
   output back, stores a log.
4. On "Run Audit" (or "Rerun"): backend uploads `server_audit.sh` +
   `gen_report.py` (+ `linux-health/` dir) if not already present/checksum
   mismatched, then runs `server_audit.sh -s [-u <url> ...] -o audit_reports`
   over SSH as a background job, downloads the resulting self-contained HTML
   report over SFTP, stores it, and marks the run `completed` (or `failed`
   with the tail of `audit_run.log` attached).
5. Dashboard shows, per server: status chip, **last run timestamp**, a
   **Rerun** button, and a **Download report** button, plus an embedded
   viewer of the latest report (it's already a self-contained HTML file —
   the dashboard iframes it directly, so you inherit the exact UI from your
   screenshot for free instead of re-parsing/re-building it).
6. Every run is kept in `AuditRun` history (status, timestamps, log tail,
   report file path) so you can go back to any previous report per server.

## 3. Why background jobs, not request/response

Lynis + Nmap + ZAP + health checks can run 15–45+ minutes (see the README's
own timing table). The API can't hold an HTTP request open that long, so:

- `POST /servers/{id}/audit-runs` immediately creates an `AuditRun` row with
  status `queued` and returns `202` with the run id.
- A **Celery worker** (Redis as broker) picks it up, flips status to
  `running`, does the SSH work, and flips to `completed`/`failed`.
- Frontend polls `GET /audit-runs/{id}` every few seconds (or a websocket,
  see §7 "future work") to update the status chip and unlock the report once
  ready.
- This also means two servers can be audited in parallel without blocking
  each other, and a stuck SSH session on one server can't wedge the whole
  app (Celery task has its own hard timeout on top of the script's own
  internal timeouts).

## 4. Security model for stored SSH credentials

This is the most sensitive part of the whole app — treat it accordingly.

- Passwords/private keys are encrypted at rest with **Fernet (AES-128-CBC +
  HMAC)** using a key from `SECRET_ENCRYPTION_KEY` (env var / secrets
  manager — never committed, never logged).
- Decrypted credentials exist only in worker process memory for the duration
  of the SSH session, then are discarded; they are never written to disk, a
  log line, or a Celery task's stored result.
- Prefer SSH **key-based** auth over passwords (the UI supports both, but
  labels password auth as "less secure" and recommends generating a
  dedicated audit-only key with restricted `command=` in the target's
  `authorized_keys` if you want defense-in-depth beyond this app).
- `AuditRun` logs are scrubbed of anything that looks like it echoed the
  password before being stored/displayed.
- Recommended production hardening (not built into the MVP, call out to
  whoever deploys this): run the Celery workers in a network segment that
  only has SSH egress to the audited hosts; rotate `SECRET_ENCRYPTION_KEY`
  via a KMS; add per-user RBAC on top of the JWT auth so not every logged-in
  user can see every project's credentials.

## 5. Data model

```
User(id, email, hashed_password, created_at)

Project(id, owner_id, name, description, created_at)

Server(
  id, project_id, name, host, port, username,
  auth_type            -- 'password' | 'private_key'
  secret_encrypted      -- Fernet blob: password or private key + passphrase
  web_targets            -- JSON list of URLs for -u flags (ZAP)
  health_env_encrypted  -- optional Fernet blob of a health.env file content
  installed_tools        -- JSON list, last known tool status from --check
  last_run_id
  created_at
)

AuditRun(
  id, server_id, run_type       -- 'install_tools' | 'audit'
  status                        -- queued | running | completed | failed
  requested_tools                -- JSON list, for install_tools runs
  flags                          -- JSON list, the exact server_audit.sh flags used
  started_at, finished_at
  log_tail                       -- last ~4000 chars of audit_run.log
  report_path                     -- path to stored .html report (audit runs only)
  summary                         -- small JSON: {grade, critical, warnings, open_ports, ...}
                                      scraped from the report for the dashboard cards
  triggered_by_user_id
)
```

`summary` is populated by a light regex/DOM-free scrape of the known
`const ... = JSON.parse(...)` blocks `gen_report.py` embeds (lynis grade,
findings counts, port counts) — see `backend/app/services/report_parser.py`.
This is intentionally best-effort: if parsing fails, the dashboard still
shows the report itself, just without the summary cards.

## 6. API surface (FastAPI)

| Method & path | Purpose |
|---|---|
| `POST /auth/register`, `/auth/login` | Basic email/password JWT auth |
| `POST /projects` / `GET /projects` | Create/list projects |
| `GET /projects/{id}` | Project detail incl. servers |
| `POST /projects/{id}/servers` | Add server (SSH creds) |
| `POST /servers/{id}/test-connection` | SSH connect + `--check`, no changes |
| `POST /servers/{id}/install-tools` | Body: `{tools: ["lynis","nmap"]}` → queues install run |
| `POST /servers/{id}/audit-runs` | Body: optional `{web_targets, health_env, full_scan}` → queues audit run |
| `GET /servers/{id}/audit-runs` | Run history for a server |
| `GET /audit-runs/{id}` | Poll status/summary |
| `GET /audit-runs/{id}/report` | Streams the stored HTML report (for iframe/download) |
| `GET /audit-runs/{id}/log` | Full run log |

## 7. Frontend (Next.js 15 / React 19, matches your existing scanner app's stack)

```
/login, /register
/projects                          Project cards, "New project"
/projects/[id]                     Server list + "Add server" modal (host/user/auth)
/projects/[id]/servers/[serverId]  Server dashboard:
                                      - status chip, last run time, Rerun, Download
                                      - "Install Tools" panel (checkboxes, dry-run preview
                                        of the exact command before confirming)
                                      - Run history table
                                      - Embedded <iframe> of latest report (sandboxed,
                                        srcDoc from the fetched HTML — matches your
                                        screenshot's tabs exactly since it *is* that HTML)
```

State: TanStack Query for polling `audit-runs/{id}` while `queued`/`running`.

## 8. What's in this scaffold vs. what you still need to wire up

Included and functional in this delivery:
- Full DB models + Alembic-free `create_all` bootstrap
- SSH executor service (paramiko) with the two locked-down commands only
- Celery tasks for install + audit runs, with timeouts
- Fernet credential encryption helper
- FastAPI routers for the full API surface above
- Next.js pages for projects/servers/dashboard wired to the API
- `docker-compose.yml` (Postgres, Redis, backend, Celery worker, frontend)

Left as follow-ups (flagged inline with `# TODO` where relevant):
- Real JWT/session hardening (the scaffold uses a minimal HS256 implementation — swap in your existing auth if you already have one from the vulnerability-scanner app)
- Websocket/live log streaming instead of polling (polling is simpler and works fine at this scale)
- RBAC beyond "owns the project"
- `report_parser.py`'s summary scraping — implemented for the common fields (grade, critical/warning counts, open ports) but should be tightened against `gen_report.py`'s exact JS variable names if that file evolves
