"""The keeper loop in login-browser/capture.py, driven with a fake browser context
(no Chrome or Playwright needed)."""
import asyncio
import importlib
import sys
import types

import pytest


@pytest.fixture
def capture(monkeypatch):
    monkeypatch.setenv("XLOGIN_SESSION_ID", "s1")
    monkeypatch.setenv("XLOGIN_CALLBACK_URL", "http://xlogin/cb")
    monkeypatch.setenv("XLOGIN_CALLBACK_TOKEN", "t")
    monkeypatch.setenv("XLOGIN_KEEPER_POLL", "30")
    monkeypatch.setenv("XLOGIN_KEEPER_TOUCH", "600")
    fake_pw = types.ModuleType("playwright.async_api")
    fake_pw.async_playwright = None
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake_pw)
    sys.path.insert(0, "login-browser")
    try:
        mod = importlib.import_module("capture")
        mod = importlib.reload(mod)
    finally:
        sys.path.remove("login-browser")
    monkeypatch.setattr(mod.asyncio, "sleep", _no_sleep)
    return mod


async def _no_sleep(*_):
    return None


class Page:
    def __init__(self, url="https://x.com/home"):
        self.url = url
        self.gotos = []

    async def evaluate(self, _):
        return "UA"

    async def goto(self, url, **_):
        self.gotos.append(url)


class Ctx:
    """Returns one cookie jar per call from a script."""
    def __init__(self, jars, page=None):
        self.jars = list(jars)
        self.pages = [page or Page()]

    async def cookies(self):
        return self.jars.pop(0) if len(self.jars) > 1 else self.jars[0]


class Chrome:
    def __init__(self, exit_after=None):
        self.n, self.exit_after = 0, exit_after

    def poll(self):
        self.n += 1
        return 0 if self.exit_after is not None and self.n > self.exit_after else None


JAR1 = [{"name": "auth_token", "value": "a"}, {"name": "ct0", "value": "c1"}]
JAR2 = [{"name": "auth_token", "value": "a"}, {"name": "ct0", "value": "c2"}]
NO_AUTH = [{"name": "ct0", "value": "c2"}]


def run(capture, monkeypatch, ctx, chrome, last, replies):
    sent = []

    def post(payload):
        sent.append(payload)
        return replies.pop(0) if replies else (200, {})

    monkeypatch.setattr(capture, "post", post)
    code = asyncio.run(capture.keep(ctx, chrome, last))
    return code, sent


def test_heartbeat_then_refresh_then_logged_out(capture, monkeypatch):
    ctx = Ctx([JAR1, JAR2, NO_AUTH])
    code, sent = run(capture, monkeypatch, ctx, Chrome(), capture.cookie_hash(JAR1), [])
    assert [p["phase"] for p in sent] == ["heartbeat", "refresh", "logged_out"]
    assert sent[1]["ct0"] == "c2" and sent[1]["user_agent"] == "UA"
    assert code == 4


def test_stops_when_service_says_so(capture, monkeypatch):
    code, sent = run(capture, monkeypatch, Ctx([JAR1]), Chrome(), capture.cookie_hash(JAR1),
                     [(200, {"stop": True})])
    assert code == 0 and len(sent) == 1


def test_stops_on_404(capture, monkeypatch):
    code, sent = run(capture, monkeypatch, Ctx([JAR1]), Chrome(), capture.cookie_hash(JAR1), [(404, {})])
    assert code == 0


def test_reports_crash_when_chrome_exits(capture, monkeypatch):
    code, sent = run(capture, monkeypatch, Ctx([JAR1]), Chrome(exit_after=1), capture.cookie_hash(JAR1), [])
    assert sent[-1]["phase"] == "crashed" and code == 3


def test_login_page_counts_as_logged_out(capture, monkeypatch):
    ctx = Ctx([JAR1], page=Page("https://x.com/i/flow/login"))
    code, sent = run(capture, monkeypatch, ctx, Chrome(), capture.cookie_hash(JAR1), [])
    assert sent == [{"phase": "logged_out", "error": "auth_token gone or sign-in page shown"}] and code == 4


def test_first_pass_reports_jar_when_no_previous_hash(capture, monkeypatch):
    code, sent = run(capture, monkeypatch, Ctx([JAR1]), Chrome(), None, [(200, {"stop": True})])
    assert sent[0]["phase"] == "refresh"


def test_keeps_going_through_short_outage(capture, monkeypatch):
    replies = [(0, {}), (0, {}), (200, {"stop": True})]
    code, sent = run(capture, monkeypatch, Ctx([JAR1]), Chrome(), capture.cookie_hash(JAR1), replies)
    assert len(sent) == 3 and code == 0


def test_cookie_hash_matches_service(capture):
    from app.service import cookie_hash
    assert capture.cookie_hash(JAR1) == cookie_hash(JAR1)
