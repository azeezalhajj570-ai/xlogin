"""Unit tests for crypto, store transitions, and the reaper."""
import time

import pytest

from app.crypto import SecretBox, new_vnc_password, sign_webhook, token_hash
from app.service import ACTIVE, LoginService
from app.store import Store
from cryptography.fernet import Fernet


def test_secretbox_roundtrip_and_rotation():
    k1, k2 = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    box = SecretBox((k1,))
    enc = box.encrypt("hello")
    assert box.decrypt(enc) == "hello"
    assert box.encrypt(None) is None and box.decrypt(None) is None
    # new box with k2 first, k1 still valid -> can decrypt old, then rotate
    box2 = SecretBox((k2, k1))
    assert box2.decrypt(enc) == "hello"
    rotated = box2.rotate(enc)
    assert SecretBox((k2,)).decrypt(rotated) == "hello"


def test_vnc_password_is_8_chars():
    assert len(new_vnc_password()) == 8


def test_webhook_signature_stable():
    sig = sign_webhook("secret", "123", b"{}")
    assert sig.startswith("sha256=") and sig == sign_webhook("secret", "123", b"{}")
    assert sig != sign_webhook("secret", "124", b"{}")


def test_terminal_transition_wipes_secrets(ctx):
    svc, store, orch, _ = ctx
    svc.create_session("acc", None, None, None)
    row = store.active_sessions()[0]
    assert row["ws_token_enc"] and row["vnc_password_enc"]
    assert store.transition(row["id"], ACTIVE, "cancelled")
    after = store.get_session(row["id"])
    assert after["ws_token_enc"] is None and after["vnc_password_enc"] is None


def test_transition_guard_blocks_terminal_resurrection(ctx):
    svc, store, orch, _ = ctx
    svc.create_session("acc", None, None, None)
    sid = store.active_sessions()[0]["id"]
    assert store.transition(sid, ACTIVE, "timeout")
    # a late "success" must not revive it
    assert store.complete_success(sid, {
        "account_id": "acc", "auth_token_enc": "x", "ct0_enc": "y", "cookies_enc": "[]"}) is False
    assert store.get_credentials("acc") is None


def test_reaper_times_out_expired(ctx):
    svc, store, orch, hooks = ctx
    svc.create_session("acc", None, None, None)
    sid = store.active_sessions()[0]["id"]
    store.update_session(sid, expires_at=time.time() - 1)  # TTL elapsed
    svc.reap()
    assert store.get_session(sid)["status"] == "timeout"
    assert orch.stopped


def test_reaper_fails_overdue_start(settings, tmp_path):
    # start_timeout=0 -> any session still 'starting' is overdue immediately
    from app.crypto import SecretBox
    from tests.conftest import FakeOrchestrator, FakeWebhooks
    from dataclasses import replace
    s = replace(settings, start_timeout=0)
    store = Store(s.database_path)
    orch = FakeOrchestrator()
    svc = LoginService(s, store, orch, SecretBox(s.encryption_keys), FakeWebhooks())
    svc.create_session("acc", None, None, None)
    sid = store.active_sessions()[0]["id"]
    time.sleep(0.01)
    svc.reap()
    assert store.get_session(sid)["status"] == "failed"


def test_reaper_kills_orphan_container(ctx):
    svc, store, orch, _ = ctx
    # a container with no matching session row
    orch.containers["xlogin-orphan"] = "ghost-session"
    svc.reap()
    assert "xlogin-orphan" in orch.stopped


def test_invalid_account_id_rejected(ctx):
    svc, *_ = ctx
    from app.service import ServiceError
    with pytest.raises(ServiceError):
        svc.create_session("has space", None, None, None)
    with pytest.raises(ServiceError):
        svc.create_session("a/b", None, None, None)


def test_resolve_vnc_token_check(ctx):
    svc, store, *_ = ctx
    svc.create_session("acc", None, None, None)
    row = store.active_sessions()[0]
    from app.service import Forbidden
    with pytest.raises(Forbidden):
        svc.resolve_vnc(row["id"], "wrong-token")
