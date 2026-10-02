import os
import sys
import time
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.api import build_app          # noqa: E402
from app.config import Settings        # noqa: E402
from app.crypto import SecretBox       # noqa: E402
from app.service import LoginService   # noqa: E402
from app.store import Store            # noqa: E402
from tests.asgi_client import ASGIClient  # noqa: E402

API_KEY = "test-api-key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


class FakeOrchestrator:
    """Stands in for Docker: records what would have been created/removed."""
    def __init__(self):
        self.started = []
        self.stopped = []
        self.containers = {}          # name -> session_id
        self.deleted_profiles = []
        self.fail_next = False

    def ping(self):
        return True

    def start(self, session_id, account_id, env):
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("boom")
        name = f"xlogin-{session_id[:12]}"
        self.started.append((name, session_id, account_id, env))
        self.containers[name] = session_id
        return name

    def stop(self, container_name):
        if container_name:
            self.stopped.append(container_name)
            self.containers.pop(container_name, None)

    def managed_containers(self):
        return [(n, s) for n, s in self.containers.items()]

    def delete_profile(self, account_id):
        self.deleted_profiles.append(account_id)


class FakeWebhooks:
    def __init__(self):
        self.events = []

    def start(self): ...
    def stop(self): ...
    def send(self, event, data):
        self.events.append((event, data))


@pytest.fixture
def settings(tmp_path):
    return Settings(
        api_keys=(API_KEY,),
        encryption_keys=(Fernet.generate_key().decode(),),
        public_base_url="https://xlogin.test",
        callback_base_url="http://xlogin:8000",
        database_path=str(tmp_path / "t.db"),
        max_sessions=2,
        session_ttl=120,
        start_timeout=30,
        reaper_interval=999,
    )


@pytest.fixture
def ctx(settings):
    store = Store(settings.database_path)
    orch = FakeOrchestrator()
    hooks = FakeWebhooks()
    svc = LoginService(settings, store, orch, SecretBox(settings.encryption_keys), hooks)
    return svc, store, orch, hooks


@pytest.fixture
def client(ctx):
    svc = ctx[0]
    app = build_app(svc)
    with ASGIClient(app) as c:
        yield c, svc, ctx[2], ctx[3]


@pytest.fixture
def auth():
    return {"Authorization": f"Bearer {API_KEY}"}
