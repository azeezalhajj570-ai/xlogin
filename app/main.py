"""Entrypoint: wires everything together and runs the reaper thread.

Run with:  uvicorn app.main:app --host 0.0.0.0 --port 8000
(the docker-compose file does this for you)
"""
from __future__ import annotations

import logging
import os
import threading
import time

from .api import build_app
from .config import Settings
from .crypto import SecretBox
from .orchestrator import Orchestrator
from .service import LoginService
from .store import Store
from .webhooks import WebhookSender

logging.basicConfig(
    level=os.getenv("XLOGIN_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("xlogin")


def create_service(settings: Settings | None = None) -> LoginService:
    settings = settings or Settings.from_env()
    store = Store(settings.database_path)
    # One Docker client per configured node (browser server).
    orchestrator = Orchestrator(None, settings)
    box = SecretBox(settings.encryption_keys)
    webhooks = WebhookSender(settings.webhook_url, settings.webhook_secret)
    webhooks.start()
    return LoginService(settings, store, orchestrator, box, webhooks)


def _reaper_loop(service: LoginService, stop: threading.Event) -> None:
    while not stop.wait(service.s.reaper_interval):
        try:
            service.reap()
        except Exception:  # noqa: BLE001
            log.exception("reaper iteration failed")


def create_app():
    service = create_service()
    app = build_app(service)
    stop = threading.Event()

    async def on_startup() -> None:
        try:
            service.orch.ping()
        except Exception:  # noqa: BLE001
            log.error("Docker is not reachable at startup; sessions will fail until it is")
        service.reap()  # clean up anything left over from a previous run
        t = threading.Thread(target=_reaper_loop, args=(service, stop), name="reaper", daemon=True)
        t.start()
        log.info("xlogin ready; public_base_url=%s", service.s.public_base_url)

    async def on_shutdown() -> None:
        stop.set()
        service.hooks.stop()

    app.add_event_handler("startup", on_startup)
    app.add_event_handler("shutdown", on_shutdown)
    return app


app = create_app()
