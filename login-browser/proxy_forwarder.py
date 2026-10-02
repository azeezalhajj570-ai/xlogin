"""A tiny localhost HTTP/HTTPS proxy that forwards to an authenticated upstream.

Chrome can't accept proxy credentials on the command line (and prompting for
them in the UI would confuse the person logging in). So when a session has a
proxy with a username/password, capture.py points Chrome at THIS forwarder on
127.0.0.1, and the forwarder injects the upstream `Proxy-Authorization` header
on the subscriber's behalf.

Scope on purpose:
  * Credentials live only in this container's memory, never on Chrome's CLI.
  * Auth is injected on the first request of each client connection, which
    covers the `CONNECT` that opens every HTTPS tunnel (all of x.com). Plain-HTTP
    keep-alive requests after the first on one connection would not get a fresh
    header, but the login flow is HTTPS, so that case doesn't arise here.
"""
from __future__ import annotations

import asyncio
import base64
import os
import sys
import urllib.parse

UPSTREAM = os.environ["XLOGIN_PROXY_URL"]
LISTEN_PORT = int(os.getenv("XLOGIN_PROXY_FORWARD_PORT", "3128"))

_u = urllib.parse.urlparse(UPSTREAM)
_auth_header = b""
if _u.username:
    creds = f"{urllib.parse.unquote(_u.username)}:{urllib.parse.unquote(_u.password or '')}"
    _auth_header = b"Proxy-Authorization: Basic " + base64.b64encode(creds.encode()) + b"\r\n"


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


async def _handle(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
    try:
        head = await client_reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
        client_writer.close()
        return
    try:
        up_reader, up_writer = await asyncio.open_connection(_u.hostname, _u.port)
    except OSError as e:
        client_writer.write(f"HTTP/1.1 502 Bad Gateway\r\n\r\nupstream proxy: {e}".encode())
        await client_writer.drain()
        client_writer.close()
        return
    request_line, rest = head.split(b"\r\n", 1)
    up_writer.write(request_line + b"\r\n" + _auth_header + rest)
    await up_writer.drain()
    await asyncio.gather(_pipe(client_reader, up_writer), _pipe(up_reader, client_writer))


async def main() -> None:
    server = await asyncio.start_server(_handle, "127.0.0.1", LISTEN_PORT)
    print(f"proxy forwarder listening on 127.0.0.1:{LISTEN_PORT} -> "
          f"{_u.hostname}:{_u.port}", file=sys.stderr, flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
