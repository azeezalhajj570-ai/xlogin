"""Minimal Docker Engine API client (stdlib only). Works over a unix socket or
tcp:// (e.g. a docker-socket-proxy that only allows the calls we need)."""
from __future__ import annotations

import http.client
import json
import socket
from urllib.parse import quote, urlencode, urlparse


class DockerError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"docker API {status}: {message}")
        self.status = status


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._path)
        self.sock = sock


class DockerClient:
    def __init__(self, host: str, api_version: str = "v1.43", timeout: float = 60):
        self.api_version = api_version
        if host.startswith("unix://"):
            path = host[len("unix://"):]
            self._connect = lambda: _UnixHTTPConnection(path, timeout)
        else:
            u = urlparse(host.replace("tcp://", "http://", 1))
            if u.scheme != "http" or not u.hostname:
                raise ValueError(f"unsupported DOCKER_HOST: {host}")
            self._connect = lambda: http.client.HTTPConnection(u.hostname, u.port or 2375, timeout=timeout)

    def _request(self, method: str, path: str, query: dict | None = None, body: dict | None = None,
                 ok: tuple[int, ...] = (200, 201, 204)):
        url = f"/{self.api_version}{path}"
        if query:
            url += "?" + urlencode(query)
        conn = self._connect()
        try:
            payload = json.dumps(body).encode() if body is not None else None
            headers = {"Content-Type": "application/json"} if payload is not None else {}
            conn.request(method, url, body=payload, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
        finally:
            conn.close()
        if resp.status not in ok:
            try:
                msg = json.loads(data).get("message", "")
            except Exception:
                msg = data[:300].decode(errors="replace")
            raise DockerError(resp.status, msg)
        if not data:
            return None
        try:
            return json.loads(data)
        except ValueError:
            return data.decode(errors="replace")

    def ping(self) -> bool:
        return self._request("GET", "/_ping") == "OK"

    def create_container(self, name: str, config: dict) -> str:
        return self._request("POST", "/containers/create", {"name": name}, config)["Id"]

    def start_container(self, ident: str) -> None:
        self._request("POST", f"/containers/{quote(ident)}/start", ok=(204, 304))

    def remove_container(self, ident: str) -> None:
        # 404 = already gone, 409 = removal already in progress (AutoRemove)
        self._request("DELETE", f"/containers/{quote(ident)}", {"force": "true"}, ok=(204, 404, 409))

    def list_containers(self, label: str) -> list[dict]:
        return self._request("GET", "/containers/json",
                             {"all": "true", "filters": json.dumps({"label": [label]})})

    def remove_volume(self, name: str) -> None:
        self._request("DELETE", f"/volumes/{quote(name)}", ok=(204, 404))
