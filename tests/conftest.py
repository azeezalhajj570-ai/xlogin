import os
import sys
import time
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.api import build_app          # noqa: E402
from app.config import Settings        # noqa: E402
from app.orchestrator import Managed, Started  # noqa: E402
from app.crypto import SecretBox       # noqa: E402
from app.service import LoginService   # noqa: E402
from app.store import Store            # noqa: E402
from tests.asgi_client import ASGIClient  # noqa: E402

API_KEY = "test-api-key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


class FakeOrchestrator:
    """Stands in for Docker: records what would have been created/removed.
    Supports several nodes, each with a slot count."""
    def __init__(self, nodes=None):
        self.nodes = dict(nodes or {"local": 50})   # name -> slots
        self.started = []             # (name, session_id, account_id, env, node, kind)
        self.stopped = []
        self.containers = {}          # name -> Managed
        self.deleted_profiles = []    # (account_id, node)
        self.copied = []              # (account_id, src, dst)
        self.memory = {}              # name -> bytes
        self.fail_next = False

    def ping(self):
        return True

    def ping_node(self, node):
        return node in self.nodes

    def node_names(self):
        return list(self.nodes)

    def slots(self, node):
        return self.nodes[node]

    def callback_base_url(self, node):
        return "http://xlogin:8000"

    def start(self, session_id, account_id, env, node=None, kind="login", run_id=None, memory=None):
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("boom")
        node = node or next(iter(self.nodes))
        run_id = run_id or session_id
        name = f"xlogin-{session_id[:12]}" if kind == "login" else f"xlogin-b-{run_id[:12]}"
        self.started.append((name, session_id, account_id, env, node, kind))
        self.containers[name] = Managed(name=name, session_id=session_id if kind == "login" else "",
                                        node=node, kind=kind, run_id=run_id)
        return Started(name=name, vnc_host=name, vnc_port=5900)

    def stop(self, container_name, node=None):
        if container_name:
            self.stopped.append(container_name)
            self.containers.pop(container_name, None)

    def set_memory(self, container_name, node, memory):
        self.memory[container_name] = memory

    def managed_containers(self):
        return list(self.containers.values())

    def delete_profile(self, account_id, node=None):
        self.deleted_profiles.append((account_id, node))

    def copy_profile(self, account_id, src, dst):
        self.copied.append((account_id, src, dst))

    # helpers for tests
    def env_of(self, session_or_run_id):
        for name, sid, acc, env, node, kind in self.started:
            if sid == session_or_run_id:
                return env
        raise AssertionError("not started")

    def add_orphan(self, name, session_id="ghost", kind="login", run_id="ghost-run", node="local"):
        self.containers[name] = Managed(name=name, session_id=session_id, node=node, kind=kind, run_id=run_id)


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
