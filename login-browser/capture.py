"""Runs inside the disposable login container.

Opens X's login page in a real **Google Chrome** (not a Playwright-launched
Chromium) on the Xvfb display the subscriber sees through noVNC. The person
completes login + any 2FA / captcha / email code themselves.

Chrome is started as an ordinary browser — its own sandbox on, no automation
switches — and the human drives it. We never automate the login itself; X blocks
Playwright-driven browsers at the username step ("We've temporarily limited your
login"), whereas a real Chrome the person drives is accepted. Playwright is used
here only to *attach* over the DevTools protocol to that already-running Chrome
and read the session cookies once they exist — it never launches or drives the
browser, so none of the automation fingerprints that trip X are present.

As soon as the `auth_token` and `ct0` cookies exist, the cookies are posted to
the service's callback. Without keep-alive the container then exits.

With keep-alive (XLOGIN_KEEP_ALIVE=1) the container stays up as the account's
live browser and runs the *keeper* loop: it reads the cookies over CDP every
XLOGIN_KEEPER_POLL seconds and reports `heartbeat`, `refresh` (the jar
changed), `logged_out` (X ended the session) or `crashed` (Chrome exited), and
reloads x.com/home every XLOGIN_KEEPER_TOUCH seconds. Both intervals are
jittered so browsers on one server don't act in step.

XLOGIN_MODE=wake starts on the saved profile at x.com/home instead of the
login flow: used to wake a sleeping account, restart a crashed browser, or
start one on another node after a move.
"""
from __future__ import annotations

import asyncio
import json
import hashlib
import os
import random
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

from playwright.async_api import async_playwright

SID = os.environ["XLOGIN_SESSION_ID"]
CALLBACK_URL = os.environ["XLOGIN_CALLBACK_URL"]
CALLBACK_TOKEN = os.environ["XLOGIN_CALLBACK_TOKEN"]
TIMEOUT = int(os.getenv("XLOGIN_LOGIN_TIMEOUT", "900"))
PREFILL_USER = os.getenv("XLOGIN_PREFILL_USER", "").strip()
PROXY_URL = os.getenv("XLOGIN_PROXY_URL", "").strip()
NO_SANDBOX = os.getenv("XLOGIN_CHROME_NO_SANDBOX", "").strip() in ("1", "true", "yes", "on")
FORWARD_PORT = int(os.getenv("XLOGIN_PROXY_FORWARD_PORT", "3128"))
CDP_PORT = int(os.getenv("XLOGIN_CDP_PORT", "9222"))
# Use the persistent profile volume when one is mounted (writable), otherwise a
# throwaway dir on the tmpfs. /profile exists in the image even with no volume,
# but the read-only rootfs makes it unwritable then — Chrome needs a writable
# user-data-dir or it exits on launch.
PROFILE_DIR = "/profile" if os.access("/profile", os.W_OK) else "/tmp/profile"
os.makedirs(PROFILE_DIR, exist_ok=True)
LOGIN_URL = "https://x.com/i/flow/login"
HOME_URL = "https://x.com/home"
MODE = os.getenv("XLOGIN_MODE", "login").strip().lower()
DEVICE = os.getenv("XLOGIN_DEVICE", "desktop").strip().lower()
USER_AGENT = os.getenv("XLOGIN_USER_AGENT", "").strip()
KEEP_ALIVE = os.getenv("XLOGIN_KEEP_ALIVE", "").strip() in ("1", "true", "yes", "on")
KEEPER_POLL = int(os.getenv("XLOGIN_KEEPER_POLL", "90"))
KEEPER_TOUCH = int(os.getenv("XLOGIN_KEEPER_TOUCH", "14400"))
# Paths that mean X is showing a sign-in / sign-out page instead of the app.
LOGGED_OUT_PATHS = ("/i/flow/login", "/login", "/logout", "/i/flow/signup", "/account/access")
CHROME = os.getenv("XLOGIN_CHROME_BINARY", "google-chrome")


def post(payload: dict) -> tuple[int, dict]:
    """POST a phase to the service. Returns (HTTP status, JSON body); status 0
    means the service could not be reached."""
    body = json.dumps(payload).encode()
    req = urllib.request.Request(CALLBACK_URL, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "X-Callback-Token": CALLBACK_TOKEN,
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        print(f"callback {payload.get('phase')} rejected: HTTP {e.code}", file=sys.stderr, flush=True)
        return e.code, {}
    except Exception as e:  # noqa: BLE001
        print(f"callback {payload.get('phase')} failed: {e}", file=sys.stderr, flush=True)
        return 0, {}


def report(payload: dict) -> bool:
    status, _ = post(payload)
    return 200 <= status < 300


def proxy_server_arg() -> str | None:
    """What to pass to Chrome's --proxy-server, or None for a direct connection.

    With credentials we route through the local forwarder (Chrome can't take
    proxy creds on the CLI); without, we point Chrome straight at the proxy.
    """
    if not PROXY_URL:
        return None
    p = urllib.parse.urlparse(PROXY_URL)
    if p.username:
        return f"http://127.0.0.1:{FORWARD_PORT}"
    return f"{p.scheme}://{p.hostname}:{p.port}"


def extract_user_id(cookies: list[dict]) -> str | None:
    # X stores the numeric user id in the `twid` cookie as "u=<id>" (url-encoded).
    for c in cookies:
        if c["name"] == "twid":
            val = urllib.parse.unquote(c["value"])
            if val.startswith("u="):
                return val[2:]
    return None


def clear_stale_singleton_locks() -> None:
    # Chromium writes SingletonLock/Cookie/Socket into the profile, keyed to the
    # container's hostname. Each session is a fresh container (new hostname) and
    # the browser is torn down rather than closed cleanly, so on a persisted
    # profile the next launch finds a foreign lock and exits immediately.
    # Remove them first; only this container uses this profile right now.
    for name in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
        try:
            os.unlink(os.path.join(PROFILE_DIR, name))
        except OSError:
            pass


def jitter(seconds: float) -> float:
    return seconds * random.uniform(0.8, 1.2)


def cookie_hash(cookies: list[dict]) -> str:
    # Must match app.service.cookie_hash: names + values only, sorted.
    pairs = sorted((str(c.get("name")), str(c.get("value"))) for c in cookies or [])
    return hashlib.sha256(json.dumps(pairs).encode()).hexdigest()


async def payload_for(ctx, jar_cookies: list[dict]) -> dict:
    jar = cookie_jar(jar_cookies)
    page = ctx.pages[0] if ctx.pages else await ctx.new_page()
    try:
        ua = await page.evaluate("navigator.userAgent")
    except Exception:  # noqa: BLE001
        ua = None
    return {
        "auth_token": jar["auth_token"],
        "ct0": jar["ct0"],
        "cookies": jar_cookies,
        "user_agent": ua,
        "x_user_id": extract_user_id(jar_cookies),
    }


def on_logged_out_page(ctx) -> bool:
    for page in ctx.pages:
        try:
            path = urllib.parse.urlparse(page.url).path
        except Exception:  # noqa: BLE001
            continue
        if any(path.startswith(p) for p in LOGGED_OUT_PATHS):
            return True
    return False


async def reload_home(ctx) -> None:
    """Load x.com/home the way a person returning to the tab would."""
    try:
        page = ctx.pages[0] if ctx.pages else await ctx.new_page()
        await page.goto(HOME_URL, wait_until="domcontentloaded", timeout=60_000)
    except Exception as e:  # noqa: BLE001
        print(f"reload failed: {e}", file=sys.stderr, flush=True)


async def keep(ctx, chrome: subprocess.Popen, last_hash: str | None) -> int:
    """Keeper loop: runs until X signs the account out, Chrome exits, or the
    service tells it to stop (sleep / disconnect / replaced by a newer run)."""
    loop = asyncio.get_event_loop()
    next_touch = loop.time() + jitter(KEEPER_TOUCH)
    unreachable = 0
    while True:
        if chrome.poll() is not None:
            post({"phase": "crashed", "error": "browser exited"})
            return 3
        try:
            jar_cookies = await ctx.cookies()
        except Exception as e:  # noqa: BLE001
            post({"phase": "crashed", "error": f"cannot read cookies: {e}"})
            return 3
        jar = cookie_jar(jar_cookies)
        if not jar.get("auth_token") or on_logged_out_page(ctx):
            post({"phase": "logged_out", "error": "auth_token gone or sign-in page shown"})
            return 4
        h = cookie_hash(jar_cookies)
        if h != last_hash and jar.get("ct0"):
            status, body = post({"phase": "refresh", **(await payload_for(ctx, jar_cookies))})
            if 200 <= status < 300:
                last_hash = h
        else:
            status, body = post({"phase": "heartbeat"})
        if status in (401, 403, 404, 410) or body.get("stop"):
            print("service asked the keeper to stop", file=sys.stderr, flush=True)
            return 0
        # Keep going through short outages of the service; give up after a
        # long one so an orphaned browser doesn't run forever.
        unreachable = unreachable + 1 if status == 0 else 0
        if unreachable * KEEPER_POLL > 6 * 3600:
            print("service unreachable for 6 h; stopping", file=sys.stderr, flush=True)
            return 5
        if loop.time() >= next_touch:
            await reload_home(ctx)
            next_touch = loop.time() + jitter(KEEPER_TOUCH)
        await asyncio.sleep(jitter(KEEPER_POLL))


def chrome_major_version() -> str | None:
    """Major version of the installed Chrome, so a synthesised UA matches the
    real binary (a mismatched version is itself a weak bot signal)."""
    try:
        out = subprocess.run([CHROME, "--version"], capture_output=True, text=True,
                             timeout=10).stdout
        m = re.search(r"\b(\d+)\.\d+", out)
        return m.group(1) if m else None
    except Exception as e:  # noqa: BLE001
        print(f"could not read Chrome version: {e}", file=sys.stderr, flush=True)
        return None


def mobile_user_agent() -> str:
    """A current Android Chrome UA matching the installed Chrome version, so
    x.com serves its real mobile site and the fingerprint stays consistent."""
    version = chrome_major_version() or "140"
    return (f"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{version}.0.0.0 Mobile Safari/537.36")


def chrome_user_agent() -> str | None:
    """The UA to launch Chrome with: an explicit override, a synthesised mobile
    UA for mobile logins, or None to keep Chrome's native desktop UA."""
    if USER_AGENT:
        return USER_AGENT
    if DEVICE == "mobile":
        return mobile_user_agent()
    return None


def launch_chrome() -> subprocess.Popen:
    args = [
        CHROME,
        f"--user-data-dir={PROFILE_DIR}",
        f"--remote-debugging-port={CDP_PORT}",
        "--remote-debugging-address=127.0.0.1",
        "--no-first-run",
        "--no-default-browser-check",
        "--password-store=basic",
        "--disable-features=Translate",
    ]
    # Size the window to the virtual screen explicitly (portrait in mobile mode),
    # so x.com lays itself out for that width. Only fall back to the window
    # manager's maximise when the screen is unparseable: passing --start-maximized
    # together with an explicit --window-size gives conflicting instructions.
    screen = os.getenv("XLOGIN_SCREEN", "1440x900x24").split("x")
    if len(screen) >= 2 and screen[0].isdigit() and screen[1].isdigit():
        args.append(f"--window-size={screen[0]},{screen[1]}")
        args.append("--window-position=0,0")
    else:
        args.append("--start-maximized")
    ua = chrome_user_agent()
    if ua:
        args.append(f"--user-agent={ua}")
    proxy = proxy_server_arg()
    if proxy:
        args.append(f"--proxy-server={proxy}")
    if NO_SANDBOX:
        # Escape hatch for hosts without unprivileged user namespaces. Normally
        # the sandbox stays ON — the "--no-sandbox" infobar is a bot signal.
        args.append("--no-sandbox")
    args.append(HOME_URL if MODE == "wake" else LOGIN_URL)
    print("launching:", " ".join(args), file=sys.stderr, flush=True)
    return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


async def wait_for_cdp(deadline: float) -> None:
    url = f"http://127.0.0.1:{CDP_PORT}/json/version"
    loop = asyncio.get_event_loop()
    while loop.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2).read()
            return
        except (urllib.error.URLError, ConnectionError, OSError):
            await asyncio.sleep(0.3)
    raise RuntimeError("Chrome DevTools endpoint never came up")


def cookie_jar(cookies: list[dict]) -> dict[str, str]:
    return {c["name"]: c["value"] for c in cookies}


async def prefill_username(ctx) -> None:
    if not PREFILL_USER:
        return
    try:
        page = ctx.pages[0] if ctx.pages else await ctx.new_page()
        field = page.locator(
            'input[autocomplete="username"], input[name="username_or_email"], input[name="text"]'
        ).first
        await field.wait_for(timeout=15_000)
        await field.fill(PREFILL_USER)
    except Exception:  # noqa: BLE001
        pass  # the person can type it themselves; prefill is a convenience only


async def wake() -> int:
    """Start on the saved profile; report ready, then keep the session."""
    clear_stale_singleton_locks()
    chrome = launch_chrome()
    loop = asyncio.get_event_loop()
    try:
        await wait_for_cdp(loop.time() + min(TIMEOUT, 120))
        async with async_playwright() as pw:
            browser = await pw.chromium.connect_over_cdp(f"http://127.0.0.1:{CDP_PORT}")
            ctx = browser.contexts[0]
            await asyncio.sleep(5)  # let x.com/home load and settle cookies
            if not cookie_jar(await ctx.cookies()).get("auth_token") or on_logged_out_page(ctx):
                post({"phase": "ready"})
                post({"phase": "logged_out", "error": "the saved profile is no longer signed in"})
                return 4
            status, body = post({"phase": "ready"})
            if status in (401, 403, 404, 410) or body.get("stop"):
                return 0
            # last_hash=None: the first pass always reports the current jar.
            return await keep(ctx, chrome, None)
    finally:
        chrome.terminate()
        try:
            chrome.wait(timeout=5)
        except subprocess.TimeoutExpired:
            chrome.kill()


async def main() -> int:
    if MODE == "wake":
        return await wake()
    clear_stale_singleton_locks()
    chrome = launch_chrome()
    loop = asyncio.get_event_loop()
    deadline = loop.time() + TIMEOUT
    try:
        await wait_for_cdp(min(deadline, loop.time() + 60))
        async with async_playwright() as pw:
            browser = await pw.chromium.connect_over_cdp(f"http://127.0.0.1:{CDP_PORT}")
            ctx = browser.contexts[0]

            # A persisted profile may already hold a valid session.
            if not cookie_jar(await ctx.cookies()).get("auth_token"):
                await prefill_username(ctx)

            report({"phase": "ready"})

            while loop.time() < deadline:
                if chrome.poll() is not None:
                    report({"phase": "failed", "error": "browser exited"})
                    return 3
                jar_cookies = await ctx.cookies()
                jar = cookie_jar(jar_cookies)
                if jar.get("auth_token") and jar.get("ct0"):
                    await asyncio.sleep(2)  # let X finish setting ct0/twid
                    jar_cookies = await ctx.cookies()
                    jar = cookie_jar(jar_cookies)
                    status, body = post({"phase": "success", **(await payload_for(ctx, jar_cookies))})
                    if not 200 <= status < 300:
                        return 2
                    if KEEP_ALIVE and body.get("keep_alive"):
                        # This container is now the account's live browser.
                        return await keep(ctx, chrome, cookie_hash(jar_cookies))
                    return 0
                await asyncio.sleep(2)

            report({"phase": "timeout"})
            return 1
    finally:
        chrome.terminate()
        try:
            chrome.wait(timeout=5)
        except subprocess.TimeoutExpired:
            chrome.kill()


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception as e:  # noqa: BLE001
        print(f"fatal: {e}", file=sys.stderr, flush=True)
        report({"phase": "failed", "error": str(e)})
        sys.exit(3)
