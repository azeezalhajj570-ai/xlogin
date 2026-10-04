"""Persistent browsers: keep-alive after login, keeper callbacks, supervision,
wake / sleep / view / move, multi-node slots and mobile mode."""
import time
from dataclasses import replace

import pytest

from app.config import ConfigError, _parse_nodes
from app.crypto import SecretBox
from app.service import BadState, Forbidden, LoginService, NoCapacity, cookie_hash
from app.store import Store
from tests.conftest import FakeOrchestrator, FakeWebhooks

COOKIES = [{"name": "auth_token", "value": "a1"}, {"name": "ct0", "value": "c1"},
           {"name": "twid", "value": "u%3D42"}]


def make(settings, nodes=None, **over):
    s = replace(settings, keep_alive=True, **over)
    store = Store(s.database_path)
    orch = FakeOrchestrator(nodes)
    hooks = FakeWebhooks()
    svc = LoginService(s, store, orch, SecretBox(s.encryption_keys), hooks)
    return svc, store, orch, hooks


def login(svc, orch, account="acc", cookies=COOKIES, x_user_id="42", device=None):
    out = svc.create_session(account, None, None, "http://u:p@proxy:1", device=device)
    sid = out["session_id"]
    tok = orch.env_of(sid)["XLOGIN_CALLBACK_TOKEN"]
    svc.handle_callback(sid, tok, {"phase": "ready"})
    res = svc.handle_callback(sid, tok, {"phase": "success", "auth_token": "a1", "ct0": "c1",
                                         "cookies": cookies, "x_user_id": x_user_id, "user_agent": "UA"})
    return sid, tok, res


def events(hooks, name):
    return [d for e, d in hooks.events if e == name]


# ---- keep-alive login -----------------------------------------------------------
def test_success_keeps_container_and_creates_live_browser(settings):
    svc, store, orch, hooks = make(settings)
    sid, tok, res = login(svc, orch)
    assert res == {"ok": True, "keep_alive": True}
    name = orch.started[0][0]
    assert name not in orch.stopped                      # container kept
    assert orch.memory[name] == svc.s.browser_memory     # lowered to the browser cap
    b = store.get_browser("acc")
    assert b["state"] == "live" and b["run_id"] == sid and b["node"] == "local"
    assert svc.box.decrypt(b["proxy_url_enc"]) == "http://u:p@proxy:1"
    assert events(hooks, "login.succeeded")[0]["browser"] == "live"
    assert svc.get_credentials("acc")["browser_state"] == "live"
    env = orch.env_of(sid)
    assert env["XLOGIN_KEEP_ALIVE"] == "1" and env["XLOGIN_MODE"] == "login"


def test_without_keep_alive_behaviour_is_unchanged(ctx):
    svc, store, orch, hooks = ctx
    sid, tok, res = login(svc, orch)
    assert res["keep_alive"] is False
    assert orch.started[0][0] in orch.stopped
    assert store.get_browser("acc") is None


def test_login_link_stops_granting_vnc_after_success(settings):
    svc, store, orch, _ = make(settings)
    out = svc.create_session("acc", None, None, None)
    sid = out["session_id"]
    ws_token = out["login_url"].split("#token=")[1]
    assert svc.resolve_vnc(sid, ws_token)[0]
    tok = orch.env_of(sid)["XLOGIN_CALLBACK_TOKEN"]
    svc.handle_callback(sid, tok, {"phase": "success", "auth_token": "a", "ct0": "b", "cookies": []})
    from app.service import Conflict
    with pytest.raises(Conflict):
        svc.resolve_vnc(sid, ws_token)


def test_new_login_refused_while_browser_live(settings):
    svc, store, orch, _ = make(settings)
    login(svc, orch)
    with pytest.raises(BadState):
        svc.create_session("acc", None, None, None)


# ---- keeper callbacks -----------------------------------------------------------
def test_refresh_updates_credentials_and_coalesces_webhooks(settings):
    svc, store, orch, hooks = make(settings)
    sid, tok, _ = login(svc, orch)
    store.update_browser("acc", last_webhook_at=0)
    # unchanged jar: heartbeat only, no webhook
    svc.handle_callback(sid, tok, {"phase": "refresh", "auth_token": "a1", "ct0": "c1", "cookies": COOKIES})
    assert not events(hooks, "session.refreshed")
    # rotated ct0 -> stored + webhook
    new = [{"name": "auth_token", "value": "a1"}, {"name": "ct0", "value": "c2"}]
    svc.handle_callback(sid, tok, {"phase": "refresh", "auth_token": "a1", "ct0": "c2",
                                   "cookies": new, "x_user_id": "42"})
    assert svc.get_credentials("acc")["ct0"] == "c2"
    assert len(events(hooks, "session.refreshed")) == 1
    # another rotation within the interval -> pending, no second webhook yet
    newer = [{"name": "auth_token", "value": "a1"}, {"name": "ct0", "value": "c3"}]
    svc.handle_callback(sid, tok, {"phase": "refresh", "auth_token": "a1", "ct0": "c3", "cookies": newer})
    assert len(events(hooks, "session.refreshed")) == 1
    assert store.get_browser("acc")["refresh_pending"] == 1
    # the supervisor flushes it once the interval has passed
    store.update_browser("acc", last_webhook_at=time.time() - 120)
    svc.reap()
    assert len(events(hooks, "session.refreshed")) == 2
    assert store.get_browser("acc")["refresh_pending"] == 0
    # payloads never carry cookies
    assert all("ct0" not in d and "cookies" not in d for d in events(hooks, "session.refreshed"))


def test_heartbeat_keeps_browser_live(settings):
    svc, store, orch, _ = make(settings)
    sid, tok, _ = login(svc, orch)
    store.update_browser("acc", last_heartbeat_at=1)
    assert svc.handle_callback(sid, tok, {"phase": "heartbeat"}) == {"ok": True}
    assert store.get_browser("acc")["last_heartbeat_at"] > time.time() - 5


def test_logged_out_stops_browser_and_notifies(settings):
    svc, store, orch, hooks = make(settings)
    sid, tok, _ = login(svc, orch)
    res = svc.handle_callback(sid, tok, {"phase": "logged_out"})
    assert res["stop"] is True
    assert store.get_browser("acc")["state"] == "logged_out"
    assert orch.started[0][0] in orch.stopped
    assert events(hooks, "session.logged_out")[0]["x_user_id"] == "42"
    # a late heartbeat is told to stop
    assert svc.handle_callback(sid, tok, {"phase": "heartbeat"})["stop"] is True
    # waking a logged-out account is refused; a new login is allowed
    with pytest.raises(BadState):
        svc.wake("acc")
    svc.create_session("acc", None, None, None)


def test_different_x_user_in_browser_counts_as_logged_out(settings):
    svc, store, orch, hooks = make(settings)
    sid, tok, _ = login(svc, orch)
    svc.handle_callback(sid, tok, {"phase": "refresh", "auth_token": "z", "ct0": "z",
                                   "cookies": [{"name": "auth_token", "value": "z"}], "x_user_id": "999"})
    assert store.get_browser("acc")["state"] == "logged_out"
    assert svc.get_credentials("acc")["auth_token"] == "a1"   # not overwritten


def test_bad_callback_token_rejected(settings):
    svc, store, orch, _ = make(settings)
    sid, tok, _ = login(svc, orch)
    with pytest.raises(Forbidden):
        svc.handle_callback(sid, "wrong", {"phase": "heartbeat"})


# ---- supervision ----------------------------------------------------------------
def test_missed_heartbeats_crash_then_restart_in_wake_mode(settings):
    svc, store, orch, hooks = make(settings)
    sid, tok, _ = login(svc, orch, device="mobile")
    store.update_browser("acc", last_heartbeat_at=time.time() - 10_000)
    svc.reap()
    b = store.get_browser("acc")
    assert b["state"] == "crashed" and b["next_restart_at"]
    assert events(hooks, "browser.crashed")[0]["gave_up"] is False
    # restart is due
    store.update_browser("acc", next_restart_at=time.time() - 1)
    svc.reap()
    b = store.get_browser("acc")
    assert b["state"] == "waking" and b["restarts"] == 1 and b["run_id"] != sid
    name, run, acc, env, node, kind = orch.started[-1]
    assert kind == "browser" and env["XLOGIN_MODE"] == "wake"
    assert env["XLOGIN_SCREEN"] == svc.s.mobile_screen           # same screen as at login
    assert env["XLOGIN_CALLBACK_URL"].endswith(f"/internal/browsers/{run}/callback")
    assert svc.box.decrypt(b["proxy_url_enc"]) == env["XLOGIN_PROXY_URL"]
    # the new container reports ready -> live
    svc.handle_browser_callback(run, env["XLOGIN_CALLBACK_TOKEN"], {"phase": "ready"})
    assert store.get_browser("acc")["state"] == "live"
    # the old container's callbacks no longer count
    from app.service import NotFound
    with pytest.raises(NotFound):
        svc.handle_callback(sid, tok, {"phase": "heartbeat"})


def test_restart_gives_up_after_max(settings):
    svc, store, orch, hooks = make(settings, browser_restart_max=1)
    login(svc, orch)
    store.update_browser("acc", restarts=1, last_heartbeat_at=0)
    svc.reap()
    b = store.get_browser("acc")
    assert b["state"] == "crashed" and b["next_restart_at"] is None
    assert events(hooks, "browser.crashed")[-1]["gave_up"] is True


def test_waking_browser_that_never_reports_crashes(settings):
    svc, store, orch, _ = make(settings)
    login(svc, orch)
    svc.sleep("acc")
    svc.wake("acc")
    store.update_browser("acc", last_heartbeat_at=time.time() - svc.s.start_timeout - 5)
    svc.reap()
    assert store.get_browser("acc")["state"] == "crashed"


def test_sweep_keeps_current_browsers_and_kills_stale_ones(settings):
    svc, store, orch, _ = make(settings)
    sid, *_ = login(svc, orch)
    adopted = orch.started[0][0]
    orch.add_orphan("xlogin-b-stale", session_id="", kind="browser", run_id="old-run")
    orch.add_orphan("xlogin-helper", kind="helper", run_id="")
    svc.reap()
    assert adopted not in orch.stopped            # the adopted login container survives
    assert "xlogin-b-stale" in orch.stopped
    assert "xlogin-helper" not in orch.stopped


def test_idle_sleep(settings):
    svc, store, orch, hooks = make(settings, browser_idle=60)
    login(svc, orch)
    store.update_browser("acc", last_used_at=time.time() - 120)
    svc.reap()
    assert store.get_browser("acc")["state"] == "sleeping"
    assert events(hooks, "browser.sleeping")[0]["reason"] == "idle"


def test_no_idle_sleep_by_default(settings):
    svc, store, orch, _ = make(settings)
    login(svc, orch)
    store.update_browser("acc", last_used_at=0)
    svc.reap()
    assert store.get_browser("acc")["state"] == "live"


# ---- wake / sleep / view ---------------------------------------------------------
def test_sleep_and_wake(settings):
    svc, store, orch, hooks = make(settings)
    login(svc, orch)
    assert svc.sleep("acc")["state"] == "sleeping"
    assert orch.started[0][0] in orch.stopped
    out = svc.wake("acc")
    assert out["state"] == "waking"
    assert svc.wake("acc")["state"] == "waking"     # idempotent while running
    assert len([s for s in orch.started if s[5] == "browser"]) == 1


def test_view_link(settings):
    svc, store, orch, _ = make(settings)
    login(svc, orch)
    v = svc.view("acc")
    run = store.get_browser("acc")["run_id"]
    assert v["view_url"].startswith(f"https://xlogin.test/view/{run}#token=")
    token = v["view_url"].split("#token=")[1]
    host, port, pw = svc.resolve_view_vnc(run, token)
    assert host and port == 5900 and len(pw) == 8
    # a new link replaces the old one
    v2 = svc.view("acc")
    with pytest.raises(Forbidden):
        svc.check_view(run, token)
    token2 = v2["view_url"].split("#token=")[1]
    assert svc.check_view(run, token2)
    # expiry
    store.update_browser("acc", view_expires_at=time.time() - 1)
    with pytest.raises(Forbidden):
        svc.check_view(run, token2)


def test_view_requires_live_browser(settings):
    svc, store, orch, _ = make(settings)
    login(svc, orch)
    svc.sleep("acc")
    with pytest.raises(BadState):
        svc.view("acc")


def test_delete_account_stops_browser(settings):
    svc, store, orch, _ = make(settings)
    login(svc, orch)
    svc.delete_account("acc")
    assert store.get_browser("acc") is None
    assert orch.started[0][0] in orch.stopped
    assert ("acc", "local") in orch.deleted_profiles


# ---- slots, nodes, move ----------------------------------------------------------
def test_slots_count_logins_and_browsers(settings):
    svc, store, orch, _ = make(settings, nodes={"b1": 2}, max_sessions=5)
    login(svc, orch, "a")                      # 1 live browser
    svc.create_session("b", None, None, None)  # + 1 login = 2 of 2
    with pytest.raises(NoCapacity):
        svc.create_session("c", None, None, None)


def test_wake_refused_when_node_full(settings):
    svc, store, orch, _ = make(settings, nodes={"b1": 1}, max_sessions=5)
    login(svc, orch, "a")
    svc.sleep("a")
    svc.create_session("b", None, None, None)   # takes the only slot
    with pytest.raises(NoCapacity):
        svc.wake("a")


def test_placement_spreads_and_returning_account_stays(settings):
    svc, store, orch, _ = make(settings, nodes={"b1": 2, "b2": 2}, max_sessions=5)
    login(svc, orch, "a")
    login(svc, orch, "b")
    assert {store.get_browser("a")["node"], store.get_browser("b")["node"]} == {"b1", "b2"}
    node_a = store.get_browser("a")["node"]
    run = store.get_browser("a")["run_id"]
    svc.handle_callback(run, orch.env_of(run)["XLOGIN_CALLBACK_TOKEN"], {"phase": "logged_out"})
    out = svc.create_session("a", None, None, None)
    assert store.get_session(out["session_id"])["node"] == node_a   # profile lives there


def test_move_copies_profile_and_restarts_on_target(settings):
    svc, store, orch, _ = make(settings, nodes={"b1": 2, "b2": 2})
    login(svc, orch, "a")
    src = store.get_browser("a")["node"]
    dst = "b2" if src == "b1" else "b1"
    out = svc.move("a", dst)
    assert orch.copied == [("a", src, dst)]
    assert ("a", src) in orch.deleted_profiles
    assert out["node"] == dst and out["state"] == "waking"
    assert orch.started[-1][4] == dst and orch.started[-1][5] == "browser"


def test_move_to_unknown_or_full_node(settings):
    svc, store, orch, _ = make(settings, nodes={"b1": 3, "b2": 1})
    login(svc, orch, "a")
    assert store.get_browser("a")["node"] == "b1"       # most free slots
    from app.service import ServiceError
    with pytest.raises(ServiceError):
        svc.move("a", "nope")
    store.upsert_browser("z", node="b2", state="live", run_id="z-run")   # b2 now full
    with pytest.raises(NoCapacity):
        svc.move("a", "b2")
    assert store.get_browser("a")["node"] == "b1" and not orch.copied


# ---- mobile mode -----------------------------------------------------------------
def test_mobile_device_sets_portrait_screen(settings):
    svc, store, orch, _ = make(settings)
    out = svc.create_session("m", None, None, None, device="mobile")
    env = orch.env_of(out["session_id"])
    assert env["XLOGIN_SCREEN"] == svc.s.mobile_screen
    assert out["device"] == "mobile"


def test_default_device_is_desktop_and_invalid_rejected(settings):
    svc, store, orch, _ = make(settings)
    out = svc.create_session("d", None, None, None)
    assert orch.env_of(out["session_id"])["XLOGIN_SCREEN"] == svc.s.desktop_screen
    from app.service import ServiceError
    with pytest.raises(ServiceError):
        svc.create_session("e", None, None, None, device="tablet")


def test_returning_account_keeps_its_screen(settings):
    svc, store, orch, _ = make(settings)
    sid, tok, _ = login(svc, orch, device="mobile")
    svc.handle_callback(sid, tok, {"phase": "logged_out"})
    out = svc.create_session("acc", None, None, None)        # no device given
    assert orch.env_of(out["session_id"])["XLOGIN_SCREEN"] == svc.s.mobile_screen


# ---- helpers / config --------------------------------------------------------------
def test_cookie_hash_ignores_order_and_attributes():
    a = [{"name": "x", "value": "1", "domain": ".x.com"}, {"name": "y", "value": "2"}]
    b = [{"name": "y", "value": "2", "path": "/"}, {"name": "x", "value": "1"}]
    assert cookie_hash(a) == cookie_hash(b)
    assert cookie_hash(a) != cookie_hash([{"name": "x", "value": "9"}])


def test_parse_nodes(monkeypatch):
    monkeypatch.setenv("XLOGIN_NODES", "b1,b2")
    monkeypatch.setenv("XLOGIN_NODE_B1_SLOTS", "2")
    monkeypatch.setenv("XLOGIN_NODE_B2_DOCKER", "tcp://10.0.0.12:2375")
    monkeypatch.setenv("XLOGIN_NODE_B2_ADDRESS", "10.0.0.12")
    monkeypatch.setenv("XLOGIN_NODE_B2_SLOTS", "6")
    monkeypatch.setenv("XLOGIN_NODE_B2_CALLBACK_BASE_URL", "http://10.0.0.10:8000")
    nodes = _parse_nodes("tcp://dockerproxy:2375", "xlogin_browsers", "http://xlogin:8000")
    b1, b2 = nodes
    assert (b1.name, b1.docker_host, b1.slots, b1.network) == ("b1", "tcp://dockerproxy:2375", 2, "xlogin_browsers")
    assert (b2.docker_host, b2.slots, b2.address, b2.network) == ("tcp://10.0.0.12:2375", 6, "10.0.0.12", "bridge")
    assert b2.callback_base_url == "http://10.0.0.10:8000"


def test_parse_nodes_default_single_node(monkeypatch):
    monkeypatch.delenv("XLOGIN_NODES", raising=False)
    (n,) = _parse_nodes("unix:///var/run/docker.sock", "net", "http://x:8000")
    assert n.name == "local" and n.docker_host == "unix:///var/run/docker.sock"


def test_config_validation(settings):
    with pytest.raises(ConfigError):
        replace(settings, keeper_poll=5).validate(allow_insecure=True)
    with pytest.raises(ConfigError):
        replace(settings, mobile_screen="big").validate(allow_insecure=True)
    with pytest.raises(ConfigError):
        replace(settings, browser_memory=100).validate(allow_insecure=True)
    replace(settings).validate(allow_insecure=True)


# ---- HTTP API ----------------------------------------------------------------------
@pytest.fixture
def kclient(settings):
    from app.api import build_app
    from tests.asgi_client import ASGIClient
    svc, store, orch, hooks = make(settings)
    with ASGIClient(build_app(svc)) as c:
        yield c, svc, store, orch


def test_browser_endpoints_need_api_key(kclient):
    c, *_ = kclient
    for method, path in (("get", "/accounts/acc/browser"), ("post", "/accounts/acc/browser"),
                         ("delete", "/accounts/acc/browser"), ("post", "/accounts/acc/view"),
                         ("post", "/accounts/acc/move"), ("get", "/nodes")):
        assert getattr(c, method)(path).status == 401


def test_browser_api_flow(kclient, auth):
    c, svc, store, orch = kclient
    assert c.get("/accounts/acc/browser", headers=auth).status == 404
    r = c.post("/sessions", json={"account_id": "acc", "device": "mobile"}, headers=auth)
    assert r.status == 201 and r.json()["device"] == "mobile"
    sid = r.json()["session_id"]
    tok = orch.env_of(sid)["XLOGIN_CALLBACK_TOKEN"]
    r = c.post(f"/internal/sessions/{sid}/callback", headers={"X-Callback-Token": tok},
               json={"phase": "success", "auth_token": "a", "ct0": "b", "cookies": COOKIES, "x_user_id": "42"})
    assert r.json()["keep_alive"] is True
    b = c.get("/accounts/acc/browser", headers=auth).json()
    assert b["state"] == "live" and b["device"] == "mobile"
    # view page + status
    v = c.post("/accounts/acc/view", headers=auth)
    assert v.status == 201
    run = store.get_browser("acc")["run_id"]
    token = v.json()["view_url"].split("#token=")[1]
    assert c.get(f"/view/{run}").status == 200
    st = c.get(f"/view/{run}/status?token={token}")
    assert st.status == 200 and st.json()["status"] == "live" and st.json()["vnc_password"]
    assert c.get(f"/view/{run}/status?token=nope").status == 403
    # sleep, wake, browser callback
    assert c.delete("/accounts/acc/browser", headers=auth).json()["state"] == "sleeping"
    assert c.post("/accounts/acc/browser", headers=auth).status == 202
    run2 = store.get_browser("acc")["run_id"]
    env = orch.env_of(run2)
    r = c.post(f"/internal/browsers/{run2}/callback", headers={"X-Callback-Token": env["XLOGIN_CALLBACK_TOKEN"]},
               json={"phase": "ready"})
    assert r.status == 200
    assert c.get("/accounts/acc/browser", headers=auth).json()["state"] == "live"
    assert c.post(f"/internal/browsers/{run2}/callback", headers={"X-Callback-Token": "bad"},
                  json={"phase": "heartbeat"}).status == 403
    # nodes + health
    assert c.get("/nodes", headers=auth).json()["nodes"][0]["used"] == 1
    assert c.get("/healthz").json()["nodes"][0]["reachable"] is True
    # move needs a node
    assert c.post("/accounts/acc/move", json={}, headers=auth).status == 400


def test_second_login_while_live_is_409(kclient, auth):
    c, svc, store, orch = kclient
    login(svc, orch)
    r = c.post("/sessions", json={"account_id": "acc"}, headers=auth)
    assert r.status == 409 and r.json()["error"] == "invalid_browser_state"
