"""Tiny dependency-free ASGI test client (no httpx/requests needed).

Drives a Starlette app's HTTP routes directly through the ASGI protocol and
runs the app's lifespan. Enough to exercise the API in tests and CI."""
from __future__ import annotations

import asyncio
import json as _json
from dataclasses import dataclass
from urllib.parse import urlencode


@dataclass
class Resp:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self):
        return _json.loads(self.body)

    @property
    def text(self):
        return self.body.decode()


class ASGIClient:
    def __init__(self, app):
        self.app = app

    def __enter__(self):
        self._loop = asyncio.new_event_loop()
        self._recv = asyncio.Queue()
        self._lifespan_done = asyncio.Event()

        async def _lifespan():
            async def receive():
                return await self._recv.get()

            async def send(msg):
                if msg["type"] in ("lifespan.startup.complete", "lifespan.shutdown.complete"):
                    self._lifespan_done.set()

            await self.app({"type": "lifespan", "asgi": {"version": "3.0"}}, receive, send)

        self._lifespan_task = self._loop.create_task(_lifespan())
        self._recv.put_nowait({"type": "lifespan.startup"})
        self._loop.run_until_complete(self._wait_event())
        return self

    def __exit__(self, *exc):
        self._lifespan_done.clear()
        self._recv.put_nowait({"type": "lifespan.shutdown"})
        self._loop.run_until_complete(self._wait_event())
        self._lifespan_task.cancel()
        self._loop.close()

    async def _wait_event(self):
        self._lifespan_done.clear() if False else None
        await self._lifespan_done.wait()

    def request(self, method: str, path: str, *, headers: dict | None = None,
                json: dict | None = None, params: dict | None = None) -> Resp:
        return self._loop.run_until_complete(self._do(method, path, headers, json, params))

    def get(self, path, **kw): return self.request("GET", path, **kw)
    def post(self, path, **kw): return self.request("POST", path, **kw)
    def delete(self, path, **kw): return self.request("DELETE", path, **kw)

    async def _do(self, method, path, headers, json, params):
        if params:
            path = f"{path}?{urlencode(params)}"
        raw_path, _, query = path.partition("?")
        hdrs = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
        body = b""
        if json is not None:
            body = _json.dumps(json).encode()
            hdrs.append((b"content-type", b"application/json"))

        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": method, "scheme": "http", "path": raw_path, "raw_path": raw_path.encode(),
            "query_string": query.encode(), "headers": hdrs,
            "client": ("127.0.0.1", 12345), "server": ("testserver", 80),
        }
        sent = {"status": 500, "headers": {}, "body": b""}
        body_sent = False

        async def receive():
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        async def send(msg):
            if msg["type"] == "http.response.start":
                sent["status"] = msg["status"]
                sent["headers"] = {k.decode(): v.decode() for k, v in msg.get("headers", [])}
            elif msg["type"] == "http.response.body":
                sent["body"] += msg.get("body", b"")

        await self.app(scope, receive, send)
        return Resp(sent["status"], sent["headers"], sent["body"])
