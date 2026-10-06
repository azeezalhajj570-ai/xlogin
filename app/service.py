"""Business logic: login sessions, persistent browsers, callbacks, supervision.

A *session* is one owner logging into their own X account. Lifecycle:

    starting ──(browser reports ready)──> waiting_for_login ──(cookies captured)──> success
        │                                      │
        └──────────────> failed / timeout <────┘ (also: cancelled)

With keep-alive on, the login container is not destroyed on success: it becomes
the account's *browser* (one row per account in `browsers`) and keeps running.

    live ──(idle / sleep)──> sleeping ──(wake)──> waking ──(ready)──> live
      │                                             │
      ├──(heartbeats stop)──> crashed ──(restart)───┘
      └──(X ends the session)──> logged_out ──(owner logs in again)──> live

All status changes are guarded transitions in SQLite, so a slow or duplicate
callback can never move a session out of a terminal state, and a callback from
a replaced container (an old run_id) can never change the current browser.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from urllib.parse import urlparse

from .config import Settings
from .crypto import SecretBox, new_token, new_vnc_password, safe_equals, token_hash
from .orchestrator import Orchestrator
from .store import ACTIVE, B_RUNNING, Store
from .webhooks import WebhookSender

log = logging.getLogger("xlogin.service")

BROWSER_PHASES = ("heartbeat", "refresh", "logged_out", "crashed")
VIEW_TTL = 600
DEVICES = ("desktop", "mobile")


class ServiceError(Exception):
    status, code = 400, "bad_request"

    def __init__(self, message: str = ""):
        super().__init__(message or self.code)
        self.message = message or self.code


class NotFound(ServiceError):
    status, code = 404, "not_found"


class Forbidden(ServiceError):
    status, code = 403, "forbidden"


class Conflict(ServiceError):
    status, code = 409, "session_already_active"


class BadState(ServiceError):
    status, code = 409, "invalid_browser_state"


class Busy(ServiceError):
    status, code = 429, "too_many_sessions"


class NoCapacity(ServiceError):
    status, code = 503, "no_browser_capacity"


class Unavailable(ServiceError):
    status, code = 503, "browser_start_failed"


def cookie_hash(cookies: list[dict]) -> str:
    """Stable fingerprint of a cookie jar (names + values only)."""
    pairs = sorted((str(c.get("name")), str(c.get("value"))) for c in cookies or [])
    return hashlib.sha256(json.dumps(pairs).encode()).hexdigest()


class LoginService:
    def __init__(self, settings: Settings, store: Store, orchestrator: Orchestrator,
                 box: SecretBox, webhooks: WebhookSender):
        self.s, self.store, self.orch, self.box, self.hooks = settings, store, orchestrator, box, webhooks

    # ---- public API: login sessions ----------------------------------------
    def create_session(self, account_id: str, username: str | None,
                        expected_user_id: str | None, proxy_url: str | None,
                        redirect_url: str | None = None, device: str | None = None) -> dict:
        """Start a login session for one owner's account. Idempotent per
        account: if one is already active, the existing session is returned."""
        account_id = self._clean_id(account_id, "account_id")
        redirect_url = self._clean_redirect(redirect_url)
        device = (device or "").strip().lower() or None
        if device and device not in DEVICES:
            raise ServiceError("device must be 'desktop' or 'mobile'")
        browser = self.store.get_browser(account_id)
        if browser and browser["state"] in B_RUNNING:
            raise BadState("this account already has a live browser; it does not need a new login")
        if browser and browser["state"] == "crashed":
            # Hold supervisor restarts while the owner logs in on the same profile.
            self.store.update_browser(account_id, next_restart_at=None)
        if not proxy_url and browser and browser.get("proxy_url_enc"):
            proxy_url = self.box.decrypt(browser["proxy_url_enc"])  # keep the account's exit IP
        # The profile volume lives on one node, so a returning account must log
        # in there; a new account goes to the node with the most free slots.
        node = browser["node"] if browser else self._pick_node()
        # A returning account keeps the screen it first logged in with (same
        # fingerprint), unless the caller asks for a specific one.
        device = device or (browser.get("device") if browser else None) or "desktop"

        now = time.time()
        sid = uuid.uuid4().hex
        ws_token = new_token()
        callback_token = new_token()
        vnc_password = new_vnc_password()

        row = {
            "id": sid,
            "account_id": account_id,
            "status": "starting",
            "container_name": None,
            "ws_token_hash": token_hash(ws_token),
            "ws_token_enc": self.box.encrypt(ws_token),
            "vnc_password_enc": self.box.encrypt(vnc_password),
            "callback_token_hash": token_hash(callback_token),
            "username": username,
            "expected_user_id": expected_user_id,
            "redirect_url": redirect_url,
            "x_user_id": None,
            "last_error": None,
            "created_at": now,
            "expires_at": now + self.s.session_ttl,
            "ready_at": None,
            "finished_at": None,
            "node": node,
            "proxy_url_enc": self.box.encrypt(proxy_url) if proxy_url else None,
            "device": device,
        }
        outcome, existing = self.store.reserve_session(row, self.s.max_sessions, self.orch.slots(node))
        if outcome == "exists":
            return self._view(existing, include_access=True)
        if outcome == "full":
            raise Busy("the maximum number of concurrent login sessions is in use; try again shortly")
        if outcome == "node_full":
            raise NoCapacity("every browser slot is in use; add capacity before connecting more accounts")

        env = {
            "XLOGIN_SESSION_ID": sid,
            "XLOGIN_CALLBACK_URL": f"{self.orch.callback_base_url(node)}/internal/sessions/{sid}/callback",
            "XLOGIN_CALLBACK_TOKEN": callback_token,
            "XLOGIN_VNC_PASSWORD": vnc_password,
            "XLOGIN_LOGIN_TIMEOUT": str(self.s.session_ttl),
            "XLOGIN_PREFILL_USER": username or "",
            "XLOGIN_EXPECTED_USER_ID": expected_user_id or "",
            "XLOGIN_PROXY_URL": proxy_url or "",
            "XLOGIN_MODE": "login",
            "XLOGIN_SCREEN": self.s.screen_for(device),
            **self._keeper_env(),
        }
        try:
            started = self.orch.start(sid, account_id, env, node=node, kind="login")
        except Exception as e:  # noqa: BLE001
            log.exception("failed to start browser for %s", sid)
            self.store.transition(sid, ("starting",), "failed", last_error=f"browser start failed: {e}")
            raise Unavailable("could not start the login browser")

        self.store.update_session(sid, container_name=started.name,
                                  vnc_host=started.vnc_host, vnc_port=started.vnc_port)
        self.hooks.send("login.started", {"session_id": sid, "account_id": account_id})
        row["container_name"] = started.name
        return self._view(row, include_access=True)

    def get_session(self, account_id: str, session_id: str) -> dict:
        row = self._owned(account_id, session_id)
        return self._view(row, include_access=True)

    def cancel_session(self, account_id: str, session_id: str) -> dict:
        row = self._owned(account_id, session_id)
        if self.store.transition(session_id, ACTIVE, "cancelled"):
            self.orch.stop(row.get("container_name"), row.get("node"))
            self.hooks.send("login.cancelled", {"session_id": session_id, "account_id": account_id})
        return self._view(self.store.get_session(session_id), include_access=False)

    # ---- callbacks from containers ------------------------------------------
    def handle_callback(self, session_id: str, callback_token: str, payload: dict) -> dict:
        """Callbacks from a login container. After a keep-alive login succeeds,
        the same container keeps reporting here as the account's browser."""
        phase = payload.get("phase")
        if phase in BROWSER_PHASES:
            browser = self.store.get_browser_by_run(session_id)
            if not browser or not browser.get("callback_token_hash"):
                raise NotFound("no live browser for this container")
            if not safe_equals(token_hash(callback_token), browser["callback_token_hash"]):
                raise Forbidden("bad callback token")
            return self._browser_event(browser, payload)

        row = self.store.get_session(session_id)
        if not row:
            raise NotFound()
        if not safe_equals(token_hash(callback_token), row["callback_token_hash"]):
            raise Forbidden("bad callback token")

        if phase == "ready":
            self.store.transition(session_id, ("starting",), "waiting_for_login", ready_at=time.time())
            return {"ok": True}

        if phase == "success":
            return self._capture(row, payload)

        if phase in ("timeout", "failed"):
            if self.store.transition(session_id, ACTIVE, phase,
                                     last_error=str(payload.get("error", ""))[:500]):
                self.orch.stop(row.get("container_name"), row.get("node"))
                self.hooks.send(f"login.{phase}",
                                {"session_id": session_id, "account_id": row["account_id"]})
            return {"ok": True}

        raise ServiceError("unknown phase")

    def handle_browser_callback(self, run_id: str, callback_token: str, payload: dict) -> dict:
        """Callbacks from a browser container started by wake / restart / move."""
        browser = self.store.get_browser_by_run(run_id)
        if not browser or not browser.get("callback_token_hash"):
            raise NotFound("no browser for this container")
        if not safe_equals(token_hash(callback_token), browser["callback_token_hash"]):
            raise Forbidden("bad callback token")
        phase = payload.get("phase")
        if phase == "ready":
            if self.store.browser_transition(browser["account_id"], ("waking",), "live", run_id=run_id,
                                             last_heartbeat_at=time.time(), last_error=None):
                log.info("browser for %s is live on %s", browser["account_id"], browser["node"])
            return {"ok": True}
        if phase in BROWSER_PHASES:
            return self._browser_event(browser, payload)
        raise ServiceError("unknown phase")

    def _capture(self, row: dict, payload: dict) -> dict:
        auth_token = (payload.get("auth_token") or "").strip()
        ct0 = (payload.get("ct0") or "").strip()
        cookies = payload.get("cookies") or []
        if not auth_token or not ct0:
            raise ServiceError("missing auth_token or ct0")

        x_user_id = payload.get("x_user_id")
        # If the caller said which X user this must be, enforce it - stops an
        # owner from accidentally connecting the wrong account.
        if row.get("expected_user_id") and x_user_id and x_user_id != row["expected_user_id"]:
            self.store.transition(row["id"], ACTIVE, "failed", last_error="logged-in user != expected user")
            self.orch.stop(row.get("container_name"), row.get("node"))
            self.hooks.send("login.failed",
                            {"session_id": row["id"], "account_id": row["account_id"],
                             "error": "wrong_account"})
            raise Forbidden("the account that logged in does not match the expected user")

        creds = {
            "account_id": row["account_id"],
            "auth_token_enc": self.box.encrypt(auth_token),
            "ct0_enc": self.box.encrypt(ct0),
            "cookies_enc": self.box.encrypt(json.dumps(cookies)),
            "user_agent": payload.get("user_agent"),
            "x_user_id": x_user_id,
        }
        # Read before complete_success wipes the session's VNC secret.
        vnc_password_enc = row.get("vnc_password_enc")
        if not self.store.complete_success(row["id"], creds):
            return {"ok": True}

        keep = self.s.keep_alive
        if keep:
            now = time.time()
            node = row.get("node") or self.s.default_node
            self.store.upsert_browser(
                row["account_id"], node=node, state="live", container_name=row.get("container_name"),
                run_id=row["id"], callback_token_hash=row["callback_token_hash"],
                vnc_password_enc=vnc_password_enc, vnc_host=row.get("vnc_host"), vnc_port=row.get("vnc_port"),
                proxy_url_enc=row.get("proxy_url_enc"), user_agent=payload.get("user_agent"),
                cookies_hash=cookie_hash(cookies), view_token_hash=None, view_expires_at=None,
                last_heartbeat_at=now, last_used_at=now, last_refresh_at=now, last_webhook_at=now,
                refresh_pending=0, restarts=0, next_restart_at=None, last_error=None, started_at=now,
                device=row.get("device") or "desktop")
            if row.get("container_name"):
                self.orch.set_memory(row["container_name"], node, self.s.browser_memory)
        else:
            self.orch.stop(row.get("container_name"), row.get("node"))
        self.hooks.send("login.succeeded",
                        {"session_id": row["id"], "account_id": row["account_id"],
                         "x_user_id": x_user_id, "browser": "live" if keep else None})
        return {"ok": True, "keep_alive": keep}

    def _browser_event(self, b: dict, payload: dict) -> dict:
        account_id, run_id = b["account_id"], b["run_id"]
        phase = payload.get("phase")
        now = time.time()
        if b["state"] not in B_RUNNING:
            # Asleep, logged out, crashed or replaced: tell the keeper to stop.
            return {"ok": True, "stop": True}

        if phase == "heartbeat":
            self.store.browser_transition(account_id, B_RUNNING, "live", run_id=run_id,
                                          last_heartbeat_at=now)
            return {"ok": True}

        if phase == "refresh":
            auth_token = (payload.get("auth_token") or "").strip()
            ct0 = (payload.get("ct0") or "").strip()
            cookies = payload.get("cookies") or []
            if not auth_token or not ct0:
                raise ServiceError("missing auth_token or ct0")
            current = self.store.get_credentials(account_id)
            x_user_id = payload.get("x_user_id")
            if current and current.get("x_user_id") and x_user_id and x_user_id != current["x_user_id"]:
                # Someone signed a different X account into this browser.
                self._end_browser(b, "logged_out", "a different X account is signed in")
                return {"ok": True, "stop": True}
            h = cookie_hash(cookies)
            self.store.browser_transition(account_id, B_RUNNING, "live", run_id=run_id,
                                          last_heartbeat_at=now)
            if h == b.get("cookies_hash"):
                return {"ok": True}
            self.store.update_credentials(account_id, {
                "auth_token_enc": self.box.encrypt(auth_token),
                "ct0_enc": self.box.encrypt(ct0),
                "cookies_enc": self.box.encrypt(json.dumps(cookies)),
                "user_agent": payload.get("user_agent"),
                "x_user_id": x_user_id,
            }, source_id=run_id)
            fields = {"cookies_hash": h, "last_refresh_at": now}
            if payload.get("user_agent"):
                fields["user_agent"] = payload["user_agent"]
            if now - (b.get("last_webhook_at") or 0) >= self.s.refresh_webhook_interval:
                fields.update(last_webhook_at=now, refresh_pending=0)
                self.store.update_browser(account_id, run_id=run_id, **fields)
                self._send_refreshed(account_id, x_user_id or (current or {}).get("x_user_id"))
            else:
                fields["refresh_pending"] = 1  # flushed by the supervisor
                self.store.update_browser(account_id, run_id=run_id, **fields)
            return {"ok": True}

        if phase == "logged_out":
            self._end_browser(b, "logged_out", str(payload.get("error") or "X ended the session")[:500])
            return {"ok": True, "stop": True}

        if phase == "crashed":
            self._crash(b, str(payload.get("error") or "browser exited")[:500])
            return {"ok": True, "stop": True}

        raise ServiceError("unknown phase")

    # ---- public API: persistent browsers --------------------------------------
    def get_browser(self, account_id: str) -> dict:
        account_id = self._clean_id(account_id, "account_id")
        b = self.store.get_browser(account_id)
        if not b:
            raise NotFound("this account has no browser")
        return self._browser_view(b)

    def wake(self, account_id: str) -> dict:
        """Start the account's browser on its saved profile. No-op if it is
        already running."""
        account_id = self._clean_id(account_id, "account_id")
        b = self.store.get_browser(account_id)
        if not b:
            raise NotFound("this account has no browser; the owner must connect it first")
        if b["state"] in B_RUNNING:
            self.store.update_browser(account_id, last_used_at=time.time())
            return self._browser_view(b)
        if b["state"] == "logged_out":
            raise BadState("X signed this account out; the owner must log in again")
        self._start_browser(b, from_states=("sleeping", "crashed"))
        return self._browser_view(self.store.get_browser(account_id))

    def sleep(self, account_id: str, reason: str = "requested") -> dict:
        """Stop the browser but keep its profile (it wakes up signed in)."""
        account_id = self._clean_id(account_id, "account_id")
        b = self.store.get_browser(account_id)
        if not b:
            raise NotFound("this account has no browser")
        if self.store.browser_transition(account_id, (*B_RUNNING, "crashed"), "sleeping",
                                         next_restart_at=None, view_token_hash=None, view_expires_at=None):
            self.orch.stop(b.get("container_name"), b["node"])
            self.hooks.send("browser.sleeping", {"account_id": account_id, "reason": reason})
        return self._browser_view(self.store.get_browser(account_id))

    def view(self, account_id: str) -> dict:
        """A short-lived link to watch and use the live browser (for a captcha or
        an email confirmation X asks for). Issuing a new link revokes the last one."""
        account_id = self._clean_id(account_id, "account_id")
        b = self.store.get_browser(account_id)
        if not b:
            raise NotFound("this account has no browser")
        if b["state"] != "live":
            raise BadState("the browser is not live; wake it first")
        token = new_token()
        expires = time.time() + VIEW_TTL
        if not self.store.update_browser(account_id, run_id=b["run_id"], view_token_hash=token_hash(token),
                                         view_expires_at=expires, last_used_at=time.time()):
            raise BadState("the browser changed; try again")
        return {"account_id": account_id,
                "view_url": f"{self.s.public_base_url}/view/{b['run_id']}#token={token}",
                "expires_in": VIEW_TTL}

    def move(self, account_id: str, node: str) -> dict:
        """Move an account's browser and profile to another node, signed in."""
        account_id = self._clean_id(account_id, "account_id")
        if node not in self.orch.node_names():
            raise ServiceError(f"unknown node {node!r}")
        b = self.store.get_browser(account_id)
        if not b:
            raise NotFound("this account has no browser")
        if b["node"] == node:
            return self._browser_view(b)
        if self.store.node_usage(node) >= self.orch.slots(node):
            raise NoCapacity(f"node {node} has no free slot")
        was_running = b["state"] in B_RUNNING or b["state"] == "crashed"
        if b["state"] in B_RUNNING:
            if not self.store.browser_transition(account_id, B_RUNNING, "sleeping"):
                raise BadState("the browser changed; try again")
            self.orch.stop(b.get("container_name"), b["node"])
        if self.s.persist_profiles:
            try:
                self.orch.copy_profile(account_id, b["node"], node)
            except Exception as e:  # noqa: BLE001
                log.exception("profile copy for %s failed", account_id)
                raise Unavailable(f"could not copy the profile: {e}")
            try:
                self.orch.delete_profile(account_id, b["node"])
            except Exception:  # noqa: BLE001
                log.warning("old profile of %s left on %s", account_id, b["node"])
        self.store.update_browser(account_id, node=node, vnc_host=None, vnc_port=None)
        b = self.store.get_browser(account_id)
        if was_running and b["state"] in ("sleeping", "crashed"):
            self._start_browser(b, from_states=("sleeping", "crashed"))
        return self._browser_view(self.store.get_browser(account_id))

    # ---- credentials (consumed by your automation workers) ------------------
    def get_credentials(self, account_id: str) -> dict:
        account_id = self._clean_id(account_id, "account_id")
        c = self.store.get_credentials(account_id)
        if not c:
            raise NotFound("no credentials stored for this account")
        b = self.store.get_browser(account_id)
        if b:
            self.store.update_browser(account_id, last_used_at=time.time())
        return {
            "account_id": account_id,
            "auth_token": self.box.decrypt(c["auth_token_enc"]),
            "ct0": self.box.decrypt(c["ct0_enc"]),
            "cookies": json.loads(self.box.decrypt(c["cookies_enc"])),
            "user_agent": c["user_agent"],
            "x_user_id": c["x_user_id"],
            "captured_at": c["captured_at"],
            "browser_state": b["state"] if b else None,
        }

    def delete_account(self, account_id: str) -> dict:
        """Full disconnect: stop the browser, wipe stored cookies and the saved profile."""
        account_id = self._clean_id(account_id, "account_id")
        b = self.store.delete_browser(account_id)
        if b:
            self.orch.stop(b.get("container_name"), b["node"])
        for row in self.store.active_sessions():
            if row["account_id"] == account_id and self.store.transition(row["id"], ACTIVE, "cancelled"):
                self.orch.stop(row.get("container_name"), row.get("node"))
        removed = self.store.delete_credentials(account_id)
        try:
            self.orch.delete_profile(account_id, b["node"] if b else None)
        except Exception:  # noqa: BLE001
            log.warning("could not delete profile volume for %s", account_id)
        return {"account_id": account_id, "deleted": removed}

    # ---- resolve a WebSocket connection to a browser's VNC --------------------
    def resolve_vnc(self, session_id: str, ws_token: str) -> tuple[str, int, str]:
        row = self.store.get_session(session_id)
        if not row or not safe_equals(token_hash(ws_token), row["ws_token_hash"]):
            raise Forbidden("invalid session or token")
        if row["status"] not in ACTIVE or not row.get("container_name"):
            raise Conflict("session is not accepting connections")
        host = row.get("vnc_host") or row["container_name"]
        port = row.get("vnc_port") or self.s.vnc_port
        return host, int(port), self.box.decrypt(row["vnc_password_enc"])

    def check_view(self, run_id: str, token: str) -> dict:
        """The browser row a view token opens, or Forbidden."""
        b = self.store.get_browser_by_run(run_id)
        if (not b or not b.get("view_token_hash") or not token
                or not safe_equals(token_hash(token), b["view_token_hash"])):
            raise Forbidden("invalid view link")
        if (b.get("view_expires_at") or 0) < time.time():
            raise Forbidden("this view link has expired")
        return b

    def resolve_view_vnc(self, run_id: str, token: str) -> tuple[str, int, str]:
        b = self.check_view(run_id, token)
        if b["state"] != "live" or not b.get("container_name"):
            raise Conflict("the browser is not live")
        host = b.get("vnc_host") or b["container_name"]
        port = b.get("vnc_port") or self.s.vnc_port
        return host, int(port), self.box.decrypt(b["vnc_password_enc"])

    # ---- background supervisor ----------------------------------------------
    def reap(self) -> None:
        now = time.time()
        for row in self.store.active_sessions():
            overdue = row["status"] == "starting" and now - row["created_at"] > self.s.start_timeout
            expired = now > row["expires_at"]
            if overdue or expired:
                reason = "failed" if overdue else "timeout"
                if self.store.transition(row["id"], ACTIVE, reason,
                                         last_error="browser never became ready" if overdue else "session expired"):
                    self.orch.stop(row.get("container_name"), row.get("node"))
                    self.hooks.send(f"login.{reason}",
                                    {"session_id": row["id"], "account_id": row["account_id"]})

        self._supervise_browsers(now)

        # Kill any container nobody owns any more (crash recovery). Containers
        # whose browser is still current are kept, so after a restart of this
        # service the running browsers are simply picked up again.
        current_runs = {b["run_id"] for b in self.store.browsers_in(B_RUNNING) if b.get("run_id")}
        for c in self.orch.managed_containers():
            if c.kind == "helper":
                continue
            if c.run_id and c.run_id in current_runs:
                continue
            if c.kind == "login":
                row = self.store.get_session(c.session_id) if c.session_id else None
                if row and row["status"] in ACTIVE:
                    continue
            self.orch.stop(c.name, c.node)

        cutoff = now - self.s.session_retention_days * 86400
        self.store.purge_sessions(cutoff)

    def _supervise_browsers(self, now: float) -> None:
        for b in self.store.browsers_in(("live", "waking")):
            grace = self.s.start_timeout if b["state"] == "waking" else self.s.heartbeat_timeout
            if now - (b.get("last_heartbeat_at") or 0) > grace:
                self._crash(b, "no heartbeat" if b["state"] == "live" else "browser never became ready")
                continue
            if b.get("refresh_pending") and now - (b.get("last_webhook_at") or 0) >= self.s.refresh_webhook_interval:
                if self.store.update_browser(b["account_id"], run_id=b["run_id"],
                                             refresh_pending=0, last_webhook_at=now):
                    creds = self.store.get_credentials(b["account_id"]) or {}
                    self._send_refreshed(b["account_id"], creds.get("x_user_id"))
            if (b["state"] == "live" and b.get("restarts")
                    and now - (b.get("started_at") or now) > 3600):
                # Stable for an hour: forget earlier crashes.
                self.store.update_browser(b["account_id"], run_id=b["run_id"], restarts=0)
            if (self.s.browser_idle and b["state"] == "live"
                    and now - (b.get("last_used_at") or now) > self.s.browser_idle):
                self.sleep(b["account_id"], reason="idle")
            if (b.get("view_expires_at") or now + 1) < now:
                self.store.update_browser(b["account_id"], run_id=b["run_id"],
                                          view_token_hash=None, view_expires_at=None)

        for b in self.store.browsers_in(("crashed",)):
            if b.get("next_restart_at") and b["next_restart_at"] <= now:
                try:
                    self._start_browser(b, from_states=("crashed",), restart=True)
                except NoCapacity:
                    # Keep it queued; it restarts when a slot frees up.
                    self.store.update_browser(b["account_id"], next_restart_at=now + 60)
                except ServiceError as e:
                    log.warning("restart of %s failed: %s", b["account_id"], e.message)

    # ---- helpers ------------------------------------------------------------
    def _start_browser(self, b: dict, from_states: tuple[str, ...], restart: bool = False) -> None:
        account_id, node = b["account_id"], b["node"]
        if node not in self.orch.node_names():
            raise BadState(f"node {node!r} is no longer configured; move the account first")
        run_id = uuid.uuid4().hex
        callback_token = new_token()
        vnc_password = new_vnc_password()
        outcome = self.store.reserve_wake(
            account_id, from_states, self.orch.slots(node),
            run_id=run_id, callback_token_hash=token_hash(callback_token),
            vnc_password_enc=self.box.encrypt(vnc_password), container_name=None,
            vnc_host=None, vnc_port=None, view_token_hash=None, view_expires_at=None,
            last_heartbeat_at=time.time(), last_used_at=time.time(), next_restart_at=None,
            started_at=time.time(),
            restarts=(b.get("restarts") or 0) + 1 if restart else 0)
        if outcome == "node_full":
            raise NoCapacity(f"node {node} has no free slot")
        if outcome != "ok":
            raise BadState("the browser is not in a state that can be woken")
        proxy_url = self.box.decrypt(b["proxy_url_enc"]) if b.get("proxy_url_enc") else ""
        env = {
            "XLOGIN_SESSION_ID": run_id,
            "XLOGIN_CALLBACK_URL": f"{self.orch.callback_base_url(node)}/internal/browsers/{run_id}/callback",
            "XLOGIN_CALLBACK_TOKEN": callback_token,
            "XLOGIN_VNC_PASSWORD": vnc_password,
            "XLOGIN_LOGIN_TIMEOUT": str(self.s.start_timeout),
            "XLOGIN_PROXY_URL": proxy_url,
            "XLOGIN_MODE": "wake",
            "XLOGIN_SCREEN": self.s.screen_for(b.get("device")),
            **self._keeper_env(),
        }
        try:
            started = self.orch.start(run_id, account_id, env, node=node, kind="browser",
                                      run_id=run_id, memory=self.s.browser_memory)
        except Exception as e:  # noqa: BLE001
            log.exception("failed to start browser for %s", account_id)
            self.store.browser_transition(account_id, ("waking",), "crashed", run_id=run_id,
                                          last_error=f"browser start failed: {e}"[:500],
                                          next_restart_at=self._next_restart(b, restart))
            raise Unavailable("could not start the browser")
        self.store.update_browser(account_id, run_id=run_id, container_name=started.name,
                                  vnc_host=started.vnc_host, vnc_port=started.vnc_port)

    def _crash(self, b: dict, reason: str) -> None:
        nxt = self._next_restart(b, restart=True)
        if self.store.browser_transition(b["account_id"], B_RUNNING, "crashed", run_id=b["run_id"],
                                         last_error=reason, next_restart_at=nxt,
                                         view_token_hash=None, view_expires_at=None):
            self.orch.stop(b.get("container_name"), b["node"])
            gave_up = nxt is None
            log.warning("browser for %s crashed (%s)%s", b["account_id"], reason,
                        "; giving up" if gave_up else "")
            self.hooks.send("browser.crashed", {"account_id": b["account_id"], "reason": reason,
                                                "restarts": b.get("restarts") or 0, "gave_up": gave_up})

    def _next_restart(self, b: dict, restart: bool) -> float | None:
        n = (b.get("restarts") or 0)
        if restart and n >= self.s.browser_restart_max:
            return None
        return time.time() + min(30 * (2 ** n), 1800)

    def _end_browser(self, b: dict, state: str, reason: str) -> None:
        if self.store.browser_transition(b["account_id"], B_RUNNING, state, run_id=b["run_id"],
                                         last_error=reason, next_restart_at=None,
                                         view_token_hash=None, view_expires_at=None):
            self.orch.stop(b.get("container_name"), b["node"])
            creds = self.store.get_credentials(b["account_id"]) or {}
            self.hooks.send("session.logged_out", {"account_id": b["account_id"],
                                                   "x_user_id": creds.get("x_user_id"), "reason": reason})

    def _send_refreshed(self, account_id: str, x_user_id: str | None) -> None:
        self.hooks.send("session.refreshed", {"account_id": account_id, "x_user_id": x_user_id,
                                              "at": int(time.time())})

    def _keeper_env(self) -> dict[str, str]:
        return {
            "XLOGIN_KEEP_ALIVE": "1" if self.s.keep_alive else "0",
            "XLOGIN_KEEPER_POLL": str(self.s.keeper_poll),
            "XLOGIN_KEEPER_TOUCH": str(self.s.keeper_touch),
        }

    def _pick_node(self) -> str:
        """The node with the most free slots (ties: configuration order)."""
        best, best_free = None, None
        for name in self.orch.node_names():
            free = self.orch.slots(name) - self.store.node_usage(name)
            if best_free is None or free > best_free:
                best, best_free = name, free
        return best or self.s.default_node

    def nodes_status(self) -> list[dict]:
        return [{"name": n, "slots": self.orch.slots(n), "used": self.store.node_usage(n)}
                for n in self.orch.node_names()]

    def _browser_view(self, b: dict) -> dict:
        return {
            "account_id": b["account_id"],
            "state": b["state"],
            "node": b["node"],
            "device": b.get("device") or "desktop",
            "last_heartbeat_at": b.get("last_heartbeat_at"),
            "last_refresh_at": b.get("last_refresh_at"),
            "restarts": b.get("restarts") or 0,
            "next_restart_at": b.get("next_restart_at"),
            "error": b.get("last_error"),
        }

    def _owned(self, account_id: str, session_id: str) -> dict:
        row = self.store.get_session(session_id)
        if not row:
            raise NotFound()
        if row["account_id"] != self._clean_id(account_id, "account_id"):
            raise NotFound()  # don't reveal that it exists under another account
        return row

    def _view(self, row: dict, include_access: bool) -> dict:
        out = {
            "session_id": row["id"],
            "account_id": row["account_id"],
            "status": row["status"],
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
            "x_user_id": row.get("x_user_id"),
            "device": row.get("device") or "desktop",
            "error": row.get("last_error"),
        }
        if include_access and row["status"] in ACTIVE and row.get("ws_token_enc"):
            token = self.box.decrypt(row["ws_token_enc"])
            out["login_url"] = (f"{self.s.public_base_url}/login/{row['id']}"
                                f"#token={token}")
            out["expires_in"] = max(0, int(row["expires_at"] - time.time()))
        return out

    @staticmethod
    def _clean_id(value: str, field: str) -> str:
        value = (value or "").strip()
        if not value or len(value) > 128 or any(c in value for c in "/\\ \t\n"):
            raise ServiceError(f"invalid {field}")
        return value

    def _clean_redirect(self, value: str | None) -> str | None:
        """Where to send the owner's browser once the login reaches a
        terminal state. Optional. Must be an absolute http(s) URL; https is
        required whenever the service itself is served over https."""
        value = (value or "").strip()
        if not value:
            return None
        if len(value) > 2048:
            raise ServiceError("redirect_url is too long")
        u = urlparse(value)
        if u.scheme not in ("http", "https") or not u.netloc:
            raise ServiceError("redirect_url must be an absolute http(s) URL")
        if u.scheme != "https" and urlparse(self.s.public_base_url).scheme == "https":
            raise ServiceError("redirect_url must be https")
        return value
