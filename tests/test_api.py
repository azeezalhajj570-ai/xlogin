"""End-to-end-ish tests against the ASGI app with a fake Docker orchestrator."""
import time

from app.crypto import token_hash


def _callback_token(svc, session_id):
    # Pull the per-session callback token the way the real container would:
    # the service generated it; we reproduce by reading what create stored is
    # impossible (only the hash is kept), so we capture it via the orchestrator.
    for name, sid, acc, env in svc.orch.started:
        if sid == session_id:
            return env["XLOGIN_CALLBACK_TOKEN"]
    raise AssertionError("session not started")


# ---- auth -------------------------------------------------------------------
def test_requires_api_key(client):
    c, *_ = client
    assert c.post("/sessions", json={"account_id": "a1"}).status == 401
    assert c.post("/sessions", json={"account_id": "a1"},
                  headers={"Authorization": "Bearer wrong"}).status == 401


def test_health(client):
    c, *_ = client
    r = c.get("/healthz")
    assert r.status == 200 and r.json()["ok"] is True


# ---- lifecycle --------------------------------------------------------------
def test_full_login_flow(client, auth):
    c, svc, orch, hooks = client
    r = c.post("/sessions", json={"account_id": "acc-1", "username": "bob"}, headers=auth)
    assert r.status == 201
    body = r.json()
    sid = body["session_id"]
    assert body["status"] == "starting"
    assert body["login_url"].startswith("https://xlogin.test/login/") and "#token=" in body["login_url"]
    assert orch.started and orch.started[0][1] == sid

    cb = _callback_token(svc, sid)
    # browser reports ready
    assert c.post(f"/internal/sessions/{sid}/callback",
                  json={"phase": "ready"}, headers={"X-Callback-Token": cb}).status == 200
    assert c.get(f"/sessions/{sid}", params={"account_id": "acc-1"}, headers=auth).json()["status"] == "waiting_for_login"

    # browser captures cookies
    assert c.post(f"/internal/sessions/{sid}/callback", json={
        "phase": "success", "auth_token": "AT123", "ct0": "CT456",
        "cookies": [{"name": "auth_token", "value": "AT123"}, {"name": "ct0", "value": "CT456"}],
        "user_agent": "Mozilla/5.0", "x_user_id": "999",
    }, headers={"X-Callback-Token": cb}).status == 200

    s = c.get(f"/sessions/{sid}", params={"account_id": "acc-1"}, headers=auth).json()
    assert s["status"] == "success" and s["x_user_id"] == "999"
    assert orch.started[0][0] in orch.stopped  # container torn down

    creds = c.get("/accounts/acc-1/credentials", headers=auth).json()
    assert creds["auth_token"] == "AT123" and creds["ct0"] == "CT456"
    assert creds["cookies"][0]["value"] == "AT123"
    assert {e for e, _ in hooks.events} >= {"login.started", "login.succeeded"}


def test_credentials_absent_is_404(client, auth):
    c, *_ = client
    assert c.get("/accounts/nobody/credentials", headers=auth).status == 404


def test_bad_callback_token_rejected(client, auth):
    c, svc, *_ = client
    sid = c.post("/sessions", json={"account_id": "acc-x"}, headers=auth).json()["session_id"]
    r = c.post(f"/internal/sessions/{sid}/callback",
               json={"phase": "ready"}, headers={"X-Callback-Token": "nope"})
    assert r.status == 403


def test_idempotent_per_account(client, auth):
    c, *_ = client
    a = c.post("/sessions", json={"account_id": "dup"}, headers=auth).json()
    b = c.post("/sessions", json={"account_id": "dup"}, headers=auth).json()
    assert a["session_id"] == b["session_id"]


def test_concurrency_limit(client, auth):
    c, svc, *_ = client  # max_sessions=2
    assert c.post("/sessions", json={"account_id": "a"}, headers=auth).status == 201
    assert c.post("/sessions", json={"account_id": "b"}, headers=auth).status == 201
    assert c.post("/sessions", json={"account_id": "cc"}, headers=auth).status == 429


def test_wrong_account_rejected(client, auth):
    c, svc, *_ = client
    sid = c.post("/sessions", json={"account_id": "acc-2", "expected_user_id": "111"},
                 headers=auth).json()["session_id"]
    cb = _callback_token(svc, sid)
    c.post(f"/internal/sessions/{sid}/callback", json={"phase": "ready"},
           headers={"X-Callback-Token": cb})
    r = c.post(f"/internal/sessions/{sid}/callback", json={
        "phase": "success", "auth_token": "x", "ct0": "y",
        "cookies": [], "x_user_id": "222",  # mismatch
    }, headers={"X-Callback-Token": cb})
    assert r.status == 403
    assert c.get(f"/sessions/{sid}", params={"account_id": "acc-2"}, headers=auth).json()["status"] == "failed"


def test_cancel(client, auth):
    c, svc, orch, _ = client
    sid = c.post("/sessions", json={"account_id": "acc-3"}, headers=auth).json()["session_id"]
    assert c.delete(f"/sessions/{sid}", params={"account_id": "acc-3"}, headers=auth).json()["status"] == "cancelled"
    assert orch.started[0][0] in orch.stopped


def test_cannot_read_another_accounts_session(client, auth):
    c, *_ = client
    sid = c.post("/sessions", json={"account_id": "owner"}, headers=auth).json()["session_id"]
    assert c.get(f"/sessions/{sid}", params={"account_id": "intruder"}, headers=auth).status == 404


def test_delete_account_wipes_everything(client, auth):
    c, svc, orch, _ = client
    sid = c.post("/sessions", json={"account_id": "gone"}, headers=auth).json()["session_id"]
    cb = _callback_token(svc, sid)
    c.post(f"/internal/sessions/{sid}/callback", json={"phase": "ready"}, headers={"X-Callback-Token": cb})
    c.post(f"/internal/sessions/{sid}/callback", json={
        "phase": "success", "auth_token": "a", "ct0": "b", "cookies": []},
        headers={"X-Callback-Token": cb})
    assert c.get("/accounts/gone/credentials", headers=auth).status == 200
    assert c.delete("/accounts/gone", headers=auth).json()["deleted"] is True
    assert c.get("/accounts/gone/credentials", headers=auth).status == 404
    assert "gone" in orch.deleted_profiles


def test_browser_start_failure_is_503(client, auth):
    c, svc, orch, _ = client
    orch.fail_next = True
    assert c.post("/sessions", json={"account_id": "boom"}, headers=auth).status == 503


# ---- status page token ------------------------------------------------------
def test_login_status_page_token(client, auth):
    c, svc, *_ = client
    body = c.post("/sessions", json={"account_id": "pg"}, headers=auth).json()
    sid = body["session_id"]
    ws_token = body["login_url"].split("#token=")[1]
    assert c.get(f"/login/{sid}/status", params={"token": ws_token}).status == 200
    assert c.get(f"/login/{sid}/status", params={"token": "bad"}).status == 403
