# xlogin — self-service X account login for SaaS automation

A small, production-ready service that lets **your subscribers log into their own
X (Twitter) accounts themselves**, through a real browser you host, so your
system can then run automation on their behalf — **without** anyone copy-pasting
`auth_token` / `ct0` out of a cookie editor.

When a subscriber clicks "Connect X account" in your app:

1. Your backend asks xlogin to start a session.
2. The subscriber opens a link and sees a **real, private Chromium** streamed to
   their browser (via noVNC over an authenticated WebSocket).
3. They log in normally — password, 2FA, email code, captcha, all of it.
4. The moment the session cookies exist, xlogin captures them, **encrypts them at
   rest**, tears down the browser, and (optionally) fires a signed webhook.
5. Your automation workers read the cookies from the credentials endpoint.

The browser is disposable (one container per login, auto-removed), runs as a
non-root user with a read-only root filesystem, and its VNC port is **never**
exposed publicly — only xlogin can reach it, and only after checking a one-time
per-session token.

```
Subscriber browser ──wss (token)──┐
                                  ▼
  Caddy (TLS) ──► xlogin service ──► VNC bridge ──► login-browser container
                       │                               (Xvfb + Chromium + x11vnc)
                       ├── SQLite (encrypted creds, session state)
                       ├── docker-socket-proxy ──► Docker (create/stop browsers)
                       └── signed webhooks ──► your backend
```

## Why this instead of manual cookies

| | Manual cookie editor | xlogin |
|---|---|---|
| Who logs in | you, by hand, per account | the account owner, self-service |
| 2FA / captcha / email codes | you juggle them | the owner handles their own |
| Tokens at rest | wherever you pasted them | encrypted (Fernet), rotatable |
| Teardown | — | browser destroyed after capture |
| Scale | one at a time | concurrent sessions, reaped automatically |

## Quick start

Prerequisites: a Linux host with Docker + Docker Compose, and a DNS name
pointing at it (for automatic HTTPS).

```bash
# 1. Secrets
make keys              # prints API key, encryption key, webhook secret
cp .env.example .env   # paste them in, set XLOGIN_DOMAIN + XLOGIN_PUBLIC_BASE_URL

# 2. Build the disposable browser image + the service, then run
make up                # == docker build ./login-browser + docker compose up -d

# 3. Health
curl https://xlogin.example.com/healthz
```

Local dev without TLS: set `XLOGIN_ALLOW_INSECURE_HTTP=1`, point
`XLOGIN_PUBLIC_BASE_URL` at `http://localhost:8000`, and run the service with
`uvicorn app.main:app` plus a local Docker socket (`DOCKER_HOST` unset).

## API

All client calls need `Authorization: Bearer <XLOGIN_API_KEYS entry>`.
`account_id` is **your** identifier for the subscriber's account — anything
stable and unique in your system.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/sessions` | Start a login. Body: `{account_id, username?, expected_user_id?, proxy_url?}`. Returns `login_url`. |
| `GET` | `/sessions/{id}?account_id=` | Poll status (`starting` → `waiting_for_login` → `success`/`failed`/`timeout`/`cancelled`). |
| `DELETE` | `/sessions/{id}?account_id=` | Cancel a login in progress. |
| `GET` | `/accounts/{account_id}/credentials` | Fetch captured `auth_token`, `ct0`, full cookie jar, user agent, `x_user_id`. |
| `DELETE` | `/accounts/{account_id}` | Disconnect: wipe stored cookies **and** the saved browser profile. |
| `GET` | `/healthz` | Liveness (DB + Docker reachability). |

Internal / not for your clients: `POST /internal/sessions/{id}/callback` (only the
login container calls this, authenticated by a per-session token) and the
`WS /sessions/{id}/vnc` bridge + `/login/{id}` page (opened by the subscriber's
browser with the per-session ws token).

See `examples/backend_client.py` for a copy-pasteable client and
`examples/webhook_receiver.py` for signature verification.

### Typical flow in your app

```python
from examples.backend_client import start_login, get_credentials

s = start_login(account_id="sub_123", username="their_handle")
# redirect the subscriber (popup / new tab) to s["login_url"]
# ...later, on the login.succeeded webhook (or by polling):
creds = get_credentials("sub_123")   # {auth_token, ct0, cookies, user_agent, x_user_id}
```

`expected_user_id` is optional but recommended if you already know which X user
id the account should be: if the person logs into the wrong account, the session
fails instead of storing the wrong cookies.

`proxy_url` is optional. If your automation for an account egresses through a
specific proxy (e.g. the subscriber's region), pass the same proxy here so the
login happens from the same network path. Format:
`http://user:pass@host:port`.

## Webhooks

Set `XLOGIN_WEBHOOK_URL` + `XLOGIN_WEBHOOK_SECRET` to receive:
`login.started`, `login.succeeded`, `login.failed`, `login.timeout`,
`login.cancelled`. Payloads are JSON and **never contain cookies** — on
`login.succeeded`, fetch them from the credentials endpoint. Each request carries:

```
X-XLogin-Timestamp: <unix seconds>
X-XLogin-Signature: sha256=<HMAC-SHA256(secret, "{timestamp}.{raw_body}")>
```

Verify both (and reject old timestamps) before trusting the event.

## Security model

- **TLS everywhere** via Caddy (auto Let's Encrypt). The service itself publishes
  no ports.
- **Credentials encrypted at rest** with Fernet; `XLOGIN_ENCRYPTION_KEYS` supports
  rotation (prepend a new key; all listed keys still decrypt).
- **The VNC stream is authenticated.** noVNC connects to the service over `wss://`
  with a single-use, per-session token (carried in the URL *fragment*, which
  browsers never send to servers or put in `Referer`). The container's VNC port
  lives only on an internal Docker network and is never published to the host.
- **Least-privilege Docker access.** The service never touches the raw Docker
  socket; it goes through `docker-socket-proxy` with only container + volume +
  POST + ping enabled.
- **Hardened browser containers:** non-root, `cap_drop: ALL`,
  `no-new-privileges`, read-only root fs, `/tmp` on tmpfs, memory/CPU/PID limits,
  `AutoRemove`.
- **Guarded state machine.** Every status change is an atomic, guarded SQLite
  transition, so a late or duplicate browser callback can't resurrect a
  cancelled/expired session or overwrite stored cookies. Per-session secrets are
  wiped the moment a session reaches a terminal state.
- **A reaper** (runs every `XLOGIN_REAPER_INTERVAL`s) times out stale sessions,
  removes orphaned containers after a crash/restart, and purges old session rows.

Operational notes:

- Put the client API behind your own network boundary too; the Bearer key is the
  only thing protecting the credentials endpoint.
- Store `.env` in a secret manager, not in git (`.gitignore` already excludes it).
- Back up the `xlogin_data` volume (the encrypted SQLite DB) and your encryption
  keys separately. Losing the keys means losing the stored cookies.
- `XLOGIN_PERSIST_PROFILES=1` keeps one browser profile per account in a Docker
  volume so returning users hit fewer "new device" / 2FA prompts. `DELETE
  /accounts/{id}` removes it. Set `0` to always start clean.

## Configuration

Everything is environment-driven; see `.env.example` for the full list with
comments. Key ones:

| Var | Default | Meaning |
|---|---|---|
| `XLOGIN_API_KEYS` | — | Comma-separated Bearer keys (≥32 chars each). |
| `XLOGIN_ENCRYPTION_KEYS` | — | Comma-separated Fernet keys; first encrypts. |
| `XLOGIN_PUBLIC_BASE_URL` | — | Public https URL subscribers reach. |
| `XLOGIN_MAX_SESSIONS` | 3 | Max concurrent login browsers. |
| `XLOGIN_SESSION_TTL` | 900 | Seconds a subscriber has to finish. |
| `XLOGIN_START_TIMEOUT` | 120 | Seconds for a browser to become ready. |
| `XLOGIN_PERSIST_PROFILES` | 1 | Keep a per-account browser profile. |
| `XLOGIN_WEBHOOK_URL` / `_SECRET` | — | Optional signed event delivery. |

## Tests

```bash
pip install pytest
pytest -q
```

The suite uses a fake Docker orchestrator and a temp SQLite DB, so it needs no
Docker daemon. It covers auth, the full login lifecycle, credential storage,
account isolation, concurrency limits, wrong-account rejection, the reaper, the
guarded transitions, and token checks. (`tests/asgi_client.py` is a tiny
dependency-free ASGI client so the tests run anywhere.)

## Scaling notes

- State is in SQLite for simplicity. For multiple service replicas, move sessions
  + credentials to Postgres (the `Store` class is the single seam to swap) and run
  the reaper in just one replica, or make `reserve_session` a Postgres advisory
  transaction. The container orchestration is already stateless.
- One login browser uses ~0.5–1.5 GB RAM while open. Size `XLOGIN_MAX_SESSIONS`
  and the host accordingly.

## A note on acceptable use

This is built for the legitimate case: subscribers connecting **their own**
accounts so your product can act for them (scheduling, publishing, analytics).
Automating accounts you don't own, or running accounts in ways X's Terms and
automation rules prohibit, can get those accounts suspended regardless of how
they logged in — and that's on you and your users, not something a login
mechanism can fix. Keep what you automate within X's developer/automation rules.
```
