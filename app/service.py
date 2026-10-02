"""Business logic: session lifecycle, browser callbacks, reaping, credentials.

A "session" is one subscriber logging into their own X account. Lifecycle:

    starting ──(browser reports ready)──> waiting_for_login ──(cookies captured)──> success
        │                                      │
        └──────────────> failed / timeout <────┘ (also: cancelled)

All status changes are guarded transitions in SQLite, so a slow or duplicate
browser callback can never move a session out of a terminal state.
"""
from __future__ import annotations

import json
import logging
import time
import uuid

from .config import Settings
from .crypto import SecretBox, new_token, new_vnc_password, safe_equals, token_hash
from .orchestrator import Orchestrator
from .store import ACTIVE, Store
from .webhooks import WebhookSender

log = logging.getLogger("xlogin.service")


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


class Busy(ServiceError):
    status, code = 429, "too_many_sessions"


class Unavailable(ServiceError):
    status, code = 503, "browser_start_failed"


class LoginService:
    def __init__(self, settings: Settings, store: Store, orchestrator: Orchestrator,
                 box: SecretBox, webhooks: WebhookSender):
        self.s, self.store, self.orch, self.box, self.hooks = settings, store, orchestrator, box, webhooks

    # ---- public API ---------------------------------------------------------
    def create_session(self, account_id: str, username: str | None,
                        expected_user_id: str | None, proxy_url: str | None) -> dict:
        """Start a login session for one subscriber's account. Idempotent per
        account: if one is already active, the existing session is returned."""
        account_id = self._clean_id(account_id, "account_id")
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
            "x_user_id": None,
            "last_error": None,
            "created_at": now,
            "expires_at": now + self.s.session_ttl,
            "ready_at": None,
            "finished_at": None,
        }
        outcome, existing = self.store.reserve_session(row, self.s.max_sessions)
        if outcome == "exists":
            return self._view(existing, include_access=True)
        if outcome == "full":
            raise Busy("the maximum number of concurrent login sessions is in use; try again shortly")

        env = {
            "XLOGIN_SESSION_ID": sid,
            "XLOGIN_CALLBACK_URL": f"{self.s.callback_base_url}/internal/sessions/{sid}/callback",
            "XLOGIN_CALLBACK_TOKEN": callback_token,
            "XLOGIN_VNC_PASSWORD": vnc_password,
            "XLOGIN_LOGIN_TIMEOUT": str(self.s.session_ttl),
            "XLOGIN_PREFILL_USER": username or "",
            "XLOGIN_EXPECTED_USER_ID": expected_user_id or "",
            "XLOGIN_PROXY_URL": proxy_url or "",
        }
        try:
            container_name = self.orch.start(sid, account_id, env)
        except Exception as e:  # noqa: BLE001
            log.exception("failed to start browser for %s", sid)
            self.store.transition(sid, ("starting",), "failed", last_error=f"browser start failed: {e}")
            raise Unavailable("could not start the login browser")

        self.store.update_session(sid, container_name=container_name)
        self.hooks.send("login.started", {"session_id": sid, "account_id": account_id})
        row["container_name"] = container_name
        return self._view(row, include_access=True)

    def get_session(self, account_id: str, session_id: str) -> dict:
        row = self._owned(account_id, session_id)
        return self._view(row, include_access=True)

    def cancel_session(self, account_id: str, session_id: str) -> dict:
        row = self._owned(account_id, session_id)
        if self.store.transition(session_id, ACTIVE, "cancelled"):
            self.orch.stop(row.get("container_name"))
            self.hooks.send("login.cancelled", {"session_id": session_id, "account_id": account_id})
        return self._view(self.store.get_session(session_id), include_access=False)

    # ---- browser callbacks (called by the container, not the API client) ----
    def handle_callback(self, session_id: str, callback_token: str, payload: dict) -> dict:
        row = self.store.get_session(session_id)
        if not row:
            raise NotFound()
        if not safe_equals(token_hash(callback_token), row["callback_token_hash"]):
            raise Forbidden("bad callback token")

        phase = payload.get("phase")
        if phase == "ready":
            self.store.transition(session_id, ("starting",), "waiting_for_login", ready_at=time.time())
            return {"ok": True}

        if phase == "success":
            return self._capture(row, payload)

        if phase in ("timeout", "failed"):
            if self.store.transition(session_id, ACTIVE, phase,
                                     last_error=str(payload.get("error", ""))[:500]):
                self.orch.stop(row.get("container_name"))
                self.hooks.send(f"login.{phase}",
                                {"session_id": session_id, "account_id": row["account_id"]})
            return {"ok": True}

        raise ServiceError("unknown phase")

    def _capture(self, row: dict, payload: dict) -> dict:
        auth_token = (payload.get("auth_token") or "").strip()
        ct0 = (payload.get("ct0") or "").strip()
        cookies = payload.get("cookies") or []
        if not auth_token or not ct0:
            raise ServiceError("missing auth_token or ct0")

        x_user_id = payload.get("x_user_id")
        # If the caller said which X user this must be, enforce it — stops a
        # subscriber from accidentally connecting the wrong account.
        if row.get("expected_user_id") and x_user_id and x_user_id != row["expected_user_id"]:
            self.store.transition(row["id"], ACTIVE, "failed", last_error="logged-in user != expected user")
            self.orch.stop(row.get("container_name"))
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
        if self.store.complete_success(row["id"], creds):
            self.orch.stop(row.get("container_name"))
            self.hooks.send("login.succeeded",
                            {"session_id": row["id"], "account_id": row["account_id"],
                             "x_user_id": x_user_id})
        return {"ok": True}

    # ---- credentials (consumed by your automation workers) ------------------
    def get_credentials(self, account_id: str) -> dict:
        account_id = self._clean_id(account_id, "account_id")
        c = self.store.get_credentials(account_id)
        if not c:
            raise NotFound("no credentials stored for this account")
        return {
            "account_id": account_id,
            "auth_token": self.box.decrypt(c["auth_token_enc"]),
            "ct0": self.box.decrypt(c["ct0_enc"]),
            "cookies": json.loads(self.box.decrypt(c["cookies_enc"])),
            "user_agent": c["user_agent"],
            "x_user_id": c["x_user_id"],
            "captured_at": c["captured_at"],
        }

    def delete_account(self, account_id: str) -> dict:
        """Full disconnect: wipe stored cookies and the saved browser profile."""
        account_id = self._clean_id(account_id, "account_id")
        removed = self.store.delete_credentials(account_id)
        try:
            self.orch.delete_profile(account_id)
        except Exception:  # noqa: BLE001
            log.warning("could not delete profile volume for %s", account_id)
        return {"account_id": account_id, "deleted": removed}

    # ---- resolve a WebSocket connection to a session's browser --------------
    def resolve_vnc(self, session_id: str, ws_token: str) -> tuple[str, int, str]:
        row = self.store.get_session(session_id)
        if not row or not safe_equals(token_hash(ws_token), row["ws_token_hash"]):
            raise Forbidden("invalid session or token")
        if row["status"] not in ACTIVE or not row.get("container_name"):
            raise Conflict("session is not accepting connections")
        return row["container_name"], self.s.vnc_port, self.box.decrypt(row["vnc_password_enc"])

    # ---- background reaper --------------------------------------------------
    def reap(self) -> None:
        now = time.time()
        for row in self.store.active_sessions():
            overdue = row["status"] == "starting" and now - row["created_at"] > self.s.start_timeout
            expired = now > row["expires_at"]
            if overdue or expired:
                reason = "failed" if overdue else "timeout"
                if self.store.transition(row["id"], ACTIVE, reason,
                                         last_error="browser never became ready" if overdue else "session expired"):
                    self.orch.stop(row.get("container_name"))
                    self.hooks.send(f"login.{reason}",
                                    {"session_id": row["id"], "account_id": row["account_id"]})

        # Kill any container whose session is already terminal / unknown (crash recovery).
        live = {sid for _, sid in self.orch.managed_containers()}
        for name, sid in self.orch.managed_containers():
            row = self.store.get_session(sid) if sid else None
            if not row or row["status"] not in ACTIVE:
                self.orch.stop(name)

        cutoff = now - self.s.session_retention_days * 86400
        self.store.purge_sessions(cutoff)

    # ---- helpers ------------------------------------------------------------
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
