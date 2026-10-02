"""Signed outbound webhooks with retries, delivered from a background thread.

Headers:  X-XLogin-Timestamp: <unix seconds>
          X-XLogin-Signature: sha256=<hex HMAC-SHA256(secret, f"{timestamp}.{raw_body}")>
Payloads never contain cookies: on `login.succeeded` fetch them from the credentials API.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
import urllib.request

from .crypto import sign_webhook

log = logging.getLogger("xlogin.webhooks")


class WebhookSender:
    def __init__(self, url: str | None, secret: str | None, attempts: int = 6, timeout: float = 10):
        self.url, self.secret = url, secret
        self.attempts, self.timeout = attempts, timeout
        self._q: queue.Queue[dict | None] = queue.Queue(maxsize=1000)
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.url and not self._thread:
            self._thread = threading.Thread(target=self._run, name="webhooks", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        if self._thread:
            self._q.put(None)
            self._thread.join(timeout=5)
            self._thread = None

    def send(self, event: str, data: dict) -> None:
        if not self.url:
            return
        try:
            self._q.put_nowait({"event": event, "sent_at": int(time.time()), "data": data})
        except queue.Full:
            log.error("webhook queue full, dropping %s", event)

    def _run(self) -> None:
        while (item := self._q.get()) is not None:
            self._deliver(item)

    def _deliver(self, item: dict) -> None:
        body = json.dumps(item, separators=(",", ":")).encode()
        for attempt in range(self.attempts):
            ts = str(int(time.time()))
            req = urllib.request.Request(self.url, data=body, method="POST", headers={
                "Content-Type": "application/json",
                "User-Agent": "xlogin-webhooks/1",
                "X-XLogin-Timestamp": ts,
                "X-XLogin-Signature": sign_webhook(self.secret, ts, body),
            })
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if 200 <= resp.status < 300:
                        return
            except Exception as e:  # noqa: BLE001
                log.warning("webhook %s attempt %d failed: %s", item["event"], attempt + 1, e)
            time.sleep(min(2 ** attempt, 60))
        log.error("webhook %s gave up after %d attempts", item["event"], self.attempts)
