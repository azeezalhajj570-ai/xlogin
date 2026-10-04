"""Authenticated WebSocket -> VNC(TCP) bridge.

noVNC in the subscriber's browser speaks RFB-over-WebSocket. Instead of exposing
each container's VNC port publicly (the old copy-paste-a-raw-port approach), the
browser connects to THIS service over wss://, we check the session's one-time
token, then stream bytes to the container's internal 5900. The VNC port is never
published to the host; it lives only on the internal docker network.
"""
from __future__ import annotations

import asyncio
import logging

from starlette.websockets import WebSocket, WebSocketDisconnect

from .service import Conflict, Forbidden, LoginService
from .store import ACTIVE

log = logging.getLogger("xlogin.vnc")

BUFFER = 65536
RECHECK_SECONDS = 5


async def vnc_websocket(ws: WebSocket, service: LoginService) -> None:
    """Bridge for an interactive login (authorised by the session's ws token)."""
    session_id = ws.path_params["session_id"]
    token = ws.query_params.get("token", "")
    try:
        host, port, _password = service.resolve_vnc(session_id, token)
    except (Forbidden, Conflict) as e:
        await ws.close(code=4403 if isinstance(e, Forbidden) else 4409, reason=e.code)
        return
    def allowed() -> bool:
        # Once the login finishes (and, with keep-alive, the container becomes
        # the account's background browser) the login link stops granting access.
        row = service.store.get_session(session_id)
        return bool(row and row["status"] in ACTIVE)

    await _bridge(ws, host, port, session_id, allowed)


async def view_vnc_websocket(ws: WebSocket, service: LoginService) -> None:
    """Bridge to an account's live browser (authorised by a short-lived view token)."""
    run_id = ws.path_params["run_id"]
    token = ws.query_params.get("token", "")
    try:
        host, port, _password = service.resolve_view_vnc(run_id, token)
    except (Forbidden, Conflict) as e:
        await ws.close(code=4403 if isinstance(e, Forbidden) else 4409, reason=e.code)
        return
    def allowed() -> bool:
        try:
            return service.check_view(run_id, token)["state"] == "live"
        except Forbidden:
            return False

    await _bridge(ws, host, port, f"view:{run_id[:12]}", allowed)


async def _bridge(ws: WebSocket, host: str, port: int, session_id: str,
                  allowed=lambda: True) -> None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
    except (OSError, asyncio.TimeoutError) as e:
        log.warning("cannot reach VNC for %s at %s:%s: %s", session_id, host, port, e)
        await ws.close(code=4502, reason="browser_unreachable")
        return

    await ws.accept(subprotocol="binary")
    log.info("vnc bridge open for session %s", session_id)

    async def ws_to_tcp() -> None:
        try:
            while True:
                msg = await ws.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                data = msg.get("bytes")
                if data is None and msg.get("text") is not None:
                    data = msg["text"].encode()
                if data:
                    writer.write(data)
                    await writer.drain()
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            writer.close()

    async def tcp_to_ws() -> None:
        try:
            while not reader.at_eof():
                data = await reader.read(BUFFER)
                if not data:
                    break
                await ws.send_bytes(data)
        except (ConnectionError, RuntimeError):
            pass
        finally:
            try:
                await ws.close()
            except RuntimeError:
                pass

    async def watchdog() -> None:
        # Close the bridge as soon as the token stops granting access (login
        # finished, view link expired or replaced, browser no longer live).
        while True:
            await asyncio.sleep(RECHECK_SECONDS)
            try:
                ok = await asyncio.to_thread(allowed)
            except Exception:  # noqa: BLE001
                ok = False
            if not ok:
                writer.close()
                try:
                    await ws.close(code=4401, reason="access_ended")
                except RuntimeError:
                    pass
                return

    tasks = [asyncio.ensure_future(t) for t in (ws_to_tcp(), tcp_to_ws())]
    dog = asyncio.ensure_future(watchdog())
    try:
        await asyncio.gather(*tasks)
    finally:
        dog.cancel()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        log.info("vnc bridge closed for session %s", session_id)
