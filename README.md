# xlogin — self-service X account login for SaaS automation

A small, production-ready service that lets **your subscribers log into their own
X (Twitter) accounts themselves**, through a real browser you host, so your
system can then run automation on their behalf — **without** anyone copy-pasting
`auth_token` / `ct0` out of a cookie editor.

When a subscriber clicks "Connect X account" in your app:

1. Your backend asks xlogin to start a session.
2. The subscriber opens a link and sees a **real, private Chrome** streamed to
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
                       │                               (Xvfb + Chrome + x11vnc)
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
| `POST` | `/sessions` | Start a login. Body: `{account_id, username?, expected_user_id?, proxy_url?, redirect_url?}`. Returns `login_url`. |
| `GET` | `/sessions/{id}?account_id=` | Poll status (`starting` → `waiting_for_login` → `success`/`failed`/`timeout`/`cancelled`). |
| `DELETE` | `/sessions/{id}?account_id=` | Cancel a login in progress. |
| `GET` | `/accounts/{account_id}/credentials` | Fetch captured `auth_token`, `ct0`, full cookie jar, user agent, `x_user_id`. |
| `DELETE` | `/accounts/{account_id}` | Disconnect: wipe stored cookies **and** the saved browser profile. |
| `GET` | `/healthz` | Liveness (DB + Docker reachability, slots per node). |
| `GET` | `/accounts/{account_id}/browser` | Persistent browser status: `live` / `waking` / `sleeping` / `crashed` / `logged_out`. |
| `POST` | `/accounts/{account_id}/browser` | Wake the browser on its saved profile (no new login). |
| `DELETE` | `/accounts/{account_id}/browser` | Put the browser to sleep (profile kept). |
| `POST` | `/accounts/{account_id}/view` | `{view_url, expires_in}`: a 10-minute link to the live browser (captcha, email code). |
| `POST` | `/accounts/{account_id}/move` | Body `{node}`: move the browser and its profile to another node, signed in. |
| `GET` | `/nodes` | Browser nodes with `slots` and `used`. |

`POST /sessions` also takes `device`: `"desktop"` (default) or `"mobile"`. See
[Mobile mode](#mobile-mode).

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
`http://user:pass@host:port`. Credentials are injected by a localhost forwarder
inside the container (Chrome can't take proxy credentials on the CLI); they are
never written to Chrome's command line. Use a **residential** proxy in the
account's usual country — datacentre IPs and region mismatches trigger X's login
limits — and give it enough bandwidth, since the browser loads the full web app.

`redirect_url` is optional. If set, the login page sends the subscriber's browser
there once the session reaches a terminal state, with the outcome appended as
query params — e.g. `https://app.example.com/connected?account_id=sub_123&status=success`
(`status` is one of `success`/`failed`/`timeout`/`cancelled`). Must be https when
the service is served over https. Use it to return the subscriber to your app
(the webhook + credentials endpoint remain the source of truth for the cookies).

### Why a real Chrome

The disposable container runs genuine Google Chrome with its own sandbox on, and
the person drives it over VNC. Playwright is used only to attach over the DevTools
protocol and read the session cookies once they exist — it never launches or
drives the browser. X blocks Playwright-/automation-launched browsers at the
username step ("We've temporarily limited your login") regardless of account or
IP; a real browser the person drives is accepted.

## Persistent browsers (keep-alive)

With `XLOGIN_KEEP_ALIVE=1` the login container is **not** destroyed after the
cookies are captured. It becomes the account's live browser and keeps running,
so the X session stays warm with the same fingerprint, IP and device trust,
and the system notices a sign-out within a couple of minutes instead of when
automation starts failing.

Inside the container, the *keeper* (in `login-browser/capture.py`) reads the
cookies over CDP every `XLOGIN_KEEPER_POLL` seconds (jittered) and reports:

| Phase | Meaning | Effect |
|---|---|---|
| `heartbeat` | still signed in, cookies unchanged | `last_heartbeat_at` |
| `refresh` | the cookie jar changed (e.g. `ct0` rotated) | credentials updated, `session.refreshed` webhook (at most one per minute per account) |
| `logged_out` | `auth_token` is gone or X shows a sign-in page | state `logged_out`, container stopped, `session.logged_out` webhook |
| `crashed` | Chrome exited | state `crashed`, restart scheduled |

It reloads `x.com/home` every `XLOGIN_KEEPER_TOUCH` seconds (jittered), the way
a person returning to the tab would. Playwright still only attaches over CDP.

**Browser states:** `live` → (sleep) → `sleeping` → (wake) → `waking` → (ready) → `live`.
Missed heartbeats (3 × poll) or a `crashed` report → `crashed` → restarted on
the saved profile with exponential backoff (30 s, 60 s, … up to 30 min), and
given up after `XLOGIN_BROWSER_RESTART_MAX` (`browser.crashed` with
`gave_up: true`). A browser that stays up for an hour has its restart count
reset. `logged_out` needs the owner to log in again; that login reuses the same
profile, proxy and screen, so X sees the same device.

**Wake / restart / move** start a container in *wake mode*: Chrome opens
`x.com/home` on the saved profile, reports `ready`, then runs the keeper. If the
profile is no longer signed in it reports `logged_out`.

**Restarts of this service** don't touch running browsers: the supervisor only
removes containers that no longer belong to a current browser or active login.

**Idle sleep** (`XLOGIN_BROWSER_IDLE`) is off by default (`0`). Set it to sleep
browsers nobody has used (credentials read, wake, view) for that many seconds.

## Browser nodes and slots

Capacity is counted in **slots**: one slot is one Chrome, **logins included**.
xlogin splits into a small control plane (API, SQLite, supervisor, VNC bridge)
and one or more **nodes**, each a Docker endpoint on a browser server.

```bash
XLOGIN_NODES=b1,b2
XLOGIN_NODE_B1_DOCKER=tcp://dockerproxy:2375     # same host as the control plane
XLOGIN_NODE_B1_SLOTS=2
XLOGIN_NODE_B2_DOCKER=tcp://10.8.0.12:2375       # docker-socket-proxy on the second server
XLOGIN_NODE_B2_ADDRESS=10.8.0.12                 # its private IP (WireGuard)
XLOGIN_NODE_B2_SLOTS=6
XLOGIN_NODE_B2_CALLBACK_BASE_URL=http://10.8.0.10:8000   # control plane, as seen from b2
```

- A new account goes to the node with the most free slots. It stays there,
  because its profile volume lives on that node.
- When every slot is taken, `POST /sessions` and wake answer `503
  no_browser_capacity`. Nothing is evicted to make room.
- A node with `ADDRESS` publishes each container's VNC port on that private IP
  only (random host port); the control plane reaches it over the private
  network. Without `ADDRESS`, containers are reached by name on the shared
  Docker network (the single-host setup).
- `POST /accounts/{id}/move {"node": "b2"}` stops the browser, copies the
  profile volume through the Docker archive API, deletes the old copy, and
  starts the browser on the new node, still signed in.
- Without `XLOGIN_NODES` there is one node, `local`, on `DOCKER_HOST` (the
  original behaviour).

On each extra browser server, run only `docker-socket-proxy` (with `CONTAINERS`,
`VOLUMES`, `POST`, `PING`), bound to the private IP, and build the
`xlogin-browser` image there. See `docker-compose.node.yml`.

**Starting point:** 2 accounts on one 1 vCPU / 4 GB server (control plane + one
node, `SLOTS=2`): worst case one live browser plus one login, about 3.2 GB.
Resize to 2 vCPU / 8 GB (`SLOTS=6`) for up to 5 accounts, then add 2 vCPU / 8 GB
nodes.

## Mobile mode

Many owners connect from a phone. `"device": "mobile"` starts the login with a
**portrait** virtual screen (`XLOGIN_MOBILE_SCREEN`, default `400x760x24`) and a
matching Chrome window, so x.com lays itself out for a narrow screen and the
remote browser shows close to 1:1 on the phone instead of a shrunken desktop.
The login page already provides an on-screen keyboard on touch devices.

Desktop Chrome keeps its normal user agent; only the window size changes, so
the browser stays a consistent, genuine Chrome. An account keeps the screen it
first logged in with across wakes, restarts, moves and later logins (screen
size is part of the browser fingerprint). Pass `device` again to change it.

Your app picks the device, typically from the owner's own user agent when they
click Connect.

## Admin link generator

`GET /admin` is an operator-only page that creates login links without the
command line: enter the API key (kept only in the browser tab), an `account_id`,
and optional `username` / `proxy_url` / `redirect_url`, and it returns a ready
`login_url` to send to the account owner. It ships no secret — every action goes
through the Bearer-authenticated `POST /sessions` — but it is **unauthenticated at
the HTTP layer**, so restrict the `/admin` path at your proxy (basic auth or an IP
allowlist).

It is also an installable PWA (web app manifest + service worker + icons): on a
phone, "Add to Home screen" / "Install app" runs it full-screen.

## Webhooks

Set `XLOGIN_WEBHOOK_URL` + `XLOGIN_WEBHOOK_SECRET` to receive:
`login.started`, `login.succeeded`, `login.failed`, `login.timeout`,
`login.cancelled`, and with keep-alive: `session.refreshed`, `session.logged_out`,
`browser.crashed` (`gave_up` tells you restarts stopped), `browser.sleeping`. Payloads are JSON and **never contain cookies** — on
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
- **Hardened browser containers:** non-root, `cap_drop: ALL`, read-only root fs,
  `/tmp` on tmpfs, memory/CPU/PID limits, `AutoRemove`. A tailored seccomp profile
  (`login-browser/seccomp-chrome.json`, Docker's default plus the syscalls a
  user-namespace sandbox needs) lets Chrome keep its **own** sandbox under
  `cap_drop: ALL`; if the profile is unavailable the browser falls back to
  `--no-sandbox`.
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
| `XLOGIN_KEEP_ALIVE` | 0 | Keep each account's browser open after login. |
| `XLOGIN_NODES` | — | Browser nodes (see [Browser nodes and slots](#browser-nodes-and-slots)). |
| `XLOGIN_BROWSER_MEMORY` | 1g | Memory cap of a live browser (logins use `XLOGIN_CONTAINER_MEMORY`). |
| `XLOGIN_BROWSER_IDLE` | 0 | Seconds unused before a live browser sleeps; 0 = never. |
| `XLOGIN_KEEPER_POLL` | 90 | Seconds between keeper checks (±20%). |
| `XLOGIN_KEEPER_TOUCH` | 14400 | Seconds between reloads of x.com/home (±20%). |
| `XLOGIN_BROWSER_RESTART_MAX` | 5 | Restarts after crashes before giving up. |
| `XLOGIN_DESKTOP_SCREEN` / `XLOGIN_MOBILE_SCREEN` | 1440x900x24 / 400x760x24 | Virtual screens. |
| `XLOGIN_NO_NEW_PRIVILEGES` | 0 | Set `no-new-privileges` on browser containers. Needs Docker CE (the snap build rejects it); `.env.example` turns it on for new installs. |

## Tests

```bash
pip install pytest
pytest -q
```

The suite uses a fake Docker orchestrator and a temp SQLite DB, so it needs no
Docker daemon. It covers auth, the full login lifecycle, credential storage,
account isolation, concurrency limits, wrong-account rejection, the reaper, the
guarded transitions, token checks, persistent browsers (keep-alive, refresh,
logged-out, crash/restart, wake/sleep/view/move), node slots and placement,
mobile mode, and the keeper loop in `capture.py` against a fake browser. (`tests/asgi_client.py` is a tiny
dependency-free ASGI client so the tests run anywhere.)

## Scaling notes

- State is in SQLite for simplicity. For multiple service replicas, move sessions
  + credentials to Postgres (the `Store` class is the single seam to swap) and run
  the reaper in just one replica, or make `reserve_session` a Postgres advisory
  transaction. The container orchestration is already stateless.
- One browser uses ~0.5–1.5 GB RAM while open. Size the node slots and the
  hosts accordingly (see [Browser nodes and slots](#browser-nodes-and-slots)).
  Add nodes to grow; the control plane only needs Postgres at around 100+ accounts.

## A note on acceptable use

This is built for the legitimate case: subscribers connecting **their own**
accounts so your product can act for them (scheduling, publishing, analytics).
Automating accounts you don't own, or running accounts in ways X's Terms and
automation rules prohibit, can get those accounts suspended regardless of how
they logged in — and that's on you and your users, not something a login
mechanism can fix. Keep what you automate within X's developer/automation rules.
```
