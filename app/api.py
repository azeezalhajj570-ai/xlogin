"""HTTP + WebSocket API (Starlette). Two trust zones:

  * Client API  (Authorization: Bearer <API key>) — your backend calls these to
    start sessions, poll status, and read captured credentials.
  * Internal callback (X-Callback-Token: per-session) — only the login container
    calls this to report readiness / cookies.
  * The /login/{id} page + /sessions/{id}/vnc WebSocket are opened by the
    subscriber's browser; they carry the per-session ws token, not an API key.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route, WebSocketRoute

from .crypto import safe_equals, token_hash
from .service import LoginService, ServiceError
from .store import ACTIVE, TERMINAL
from .vnc_gateway import vnc_websocket

log = logging.getLogger("xlogin.api")
STATIC = Path(__file__).parent / "static"
MAX_BODY = 256 * 1024


def _err(e: ServiceError) -> JSONResponse:
    return JSONResponse({"error": e.code, "message": e.message}, status_code=e.status)


def _with_params(url: str, **params: str) -> str:
    """Append query params to a URL, preserving any it already has."""
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query += [(k, v) for k, v in params.items() if v is not None]
    return urlunsplit(parts._replace(query=urlencode(query)))


async def _read_json(request: Request) -> dict:
    body = await request.body()
    if len(body) > MAX_BODY:
        raise ServiceError("request body too large")
    if not body:
        return {}
    import json
    try:
        data = json.loads(body)
    except ValueError:
        raise ServiceError("invalid JSON")
    if not isinstance(data, dict):
        raise ServiceError("expected a JSON object")
    return data


def build_app(service: LoginService) -> Starlette:
    settings = service.s

    def _check_key(request: Request) -> JSONResponse | None:
        header = request.headers.get("authorization", "")
        presented = header[7:].strip() if header[:7].lower() == "bearer " else ""
        if not presented or not any(safe_equals(presented, k) for k in settings.api_keys):
            return JSONResponse({"error": "unauthorized"}, status_code=401,
                                headers={"WWW-Authenticate": "Bearer"})
        return None

    # ---- client API --------------------------------------------------------
    async def create_session(request: Request):
        if (deny := _check_key(request)):
            return deny
        try:
            body = await _read_json(request)
            account_id = body.get("account_id")
            if not account_id:
                raise ServiceError("account_id is required")
            result = service.create_session(
                account_id=str(account_id),
                username=(str(body["username"]) if body.get("username") else None),
                expected_user_id=(str(body["expected_user_id"]) if body.get("expected_user_id") else None),
                proxy_url=(str(body["proxy_url"]) if body.get("proxy_url") else None),
                redirect_url=(str(body["redirect_url"]) if body.get("redirect_url") else None),
            )
            return JSONResponse(result, status_code=201)
        except ServiceError as e:
            return _err(e)

    async def get_session(request: Request):
        if (deny := _check_key(request)):
            return deny
        try:
            return JSONResponse(service.get_session(
                request.query_params.get("account_id", ""), request.path_params["session_id"]))
        except ServiceError as e:
            return _err(e)

    async def cancel_session(request: Request):
        if (deny := _check_key(request)):
            return deny
        try:
            return JSONResponse(service.cancel_session(
                request.query_params.get("account_id", ""), request.path_params["session_id"]))
        except ServiceError as e:
            return _err(e)

    async def get_credentials(request: Request):
        if (deny := _check_key(request)):
            return deny
        try:
            return JSONResponse(service.get_credentials(request.path_params["account_id"]))
        except ServiceError as e:
            return _err(e)

    async def delete_account(request: Request):
        if (deny := _check_key(request)):
            return deny
        try:
            return JSONResponse(service.delete_account(request.path_params["account_id"]))
        except ServiceError as e:
            return _err(e)

    # ---- internal callback (from the login container) ----------------------
    async def callback(request: Request):
        token = request.headers.get("x-callback-token", "")
        try:
            body = await _read_json(request)
            return JSONResponse(service.handle_callback(
                request.path_params["session_id"], token, body))
        except ServiceError as e:
            return _err(e)

    # ---- subscriber-facing login page --------------------------------------
    async def login_page(request: Request):
        # The page itself carries no secret; the ws token stays in the URL
        # fragment (#token=...) which browsers never send to the server or
        # include in Referer headers. JS reads it and opens the WebSocket.
        return FileResponse(STATIC / "login.html", headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy":
                "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
        })

    async def login_status(request: Request):
        # Read-only status for the login page, authorised by the per-session ws
        # token (fragment -> query by the page's JS). No account data leaks.
        try:
            row = service.store.get_session(request.path_params["session_id"])
            token = request.query_params.get("token", "")
            if not row or not safe_equals(token_hash(token), row["ws_token_hash"]):
                return JSONResponse({"error": "forbidden"}, status_code=403)
            body = {"status": row["status"],
                    "expires_in": max(0, int(row["expires_at"] - time.time()))}
            # On a terminal state, if the caller supplied a return URL, hand the
            # page a ready-to-use target carrying the outcome so it can send the
            # subscriber back to the app (e.g. the Odoo x-account module).
            if row["status"] in TERMINAL and row.get("redirect_url"):
                body["redirect_to"] = _with_params(
                    row["redirect_url"],
                    account_id=row["account_id"], status=row["status"])
            # On success, hand the captured auth_token/ct0 to the page so the
            # operator can copy them straight into their importer. This is gated
            # by the one-time ws token and the link is short-lived; the person
            # holding it is the account owner who just authenticated, so they are
            # only being shown their own session cookies.
            if row["status"] == "success":
                creds = service.store.get_credentials(row["account_id"])
                if creds:
                    at = service.box.decrypt(creds["auth_token_enc"])
                    ct0 = service.box.decrypt(creds["ct0_enc"])
                    body["credentials"] = {
                        "auth_token": at,
                        "ct0": ct0,
                        "cookie": f"auth_token={at}; ct0={ct0}",
                        "x_user_id": creds.get("x_user_id"),
                    }
            # The VNC server behind the bridge requires a password. The page is
            # already authorised by the one-time ws token, so hand it the
            # session's VNC password to pass to noVNC. The password only guards
            # the internal VNC port between concurrent sessions; it is never
            # reused and the container is destroyed on completion.
            if row["status"] in ACTIVE and row.get("vnc_password_enc"):
                body["vnc_password"] = service.box.decrypt(row["vnc_password_enc"])
            return JSONResponse(body, headers={"Cache-Control": "no-store"})
        except Exception:  # noqa: BLE001
            return JSONResponse({"error": "error"}, status_code=500)

    async def static_file(request: Request):
        rel = request.path_params["path"]
        target = (STATIC / rel).resolve()
        if not str(target).startswith(str(STATIC.resolve())) or not target.is_file():
            return Response(status_code=404)
        return FileResponse(target, headers={"Cache-Control": "public, max-age=3600"})

    async def health(request: Request):
        ok = True
        detail = {}
        try:
            detail["db"] = service.store.ping()
        except Exception as e:  # noqa: BLE001
            ok, detail["db"], detail["db_error"] = False, False, str(e)
        try:
            detail["docker"] = service.orch.ping()
        except Exception as e:  # noqa: BLE001
            ok, detail["docker"], detail["docker_error"] = False, False, str(e)
        return JSONResponse({"ok": ok, **detail}, status_code=200 if ok else 503)

    async def vnc(ws):
        await vnc_websocket(ws, service)

    routes = [
        Route("/healthz", health),
        Route("/sessions", create_session, methods=["POST"]),
        Route("/sessions/{session_id}", get_session, methods=["GET"]),
        Route("/sessions/{session_id}", cancel_session, methods=["DELETE"]),
        Route("/accounts/{account_id}/credentials", get_credentials, methods=["GET"]),
        Route("/accounts/{account_id}", delete_account, methods=["DELETE"]),
        Route("/internal/sessions/{session_id}/callback", callback, methods=["POST"]),
        Route("/login/{session_id}", login_page, methods=["GET"]),
        Route("/login/{session_id}/status", login_status, methods=["GET"]),
        Route("/static/{path:path}", static_file, methods=["GET"]),
        WebSocketRoute("/sessions/{session_id}/vnc", vnc),
    ]

    app = Starlette(routes=routes)
    app.state.settings = settings
    app.state.service = service
    return app
