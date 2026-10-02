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
the service's callback and the container exits.
"""
from __future__ import annotations

import asyncio
import json
import os
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
CHROME = os.getenv("XLOGIN_CHROME_BINARY", "google-chrome")


def report(payload: dict) -> bool:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(CALLBACK_URL, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "X-Callback-Token": CALLBACK_TOKEN,
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return 200 <= resp.status < 300
    except Exception as e:  # noqa: BLE001
        print(f"callback failed: {e}", file=sys.stderr, flush=True)
        return False


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
        "--start-maximized",
    ]
    proxy = proxy_server_arg()
    if proxy:
        args.append(f"--proxy-server={proxy}")
    if NO_SANDBOX:
        # Escape hatch for hosts without unprivileged user namespaces. Normally
        # the sandbox stays ON — the "--no-sandbox" infobar is a bot signal.
        args.append("--no-sandbox")
    args.append(LOGIN_URL)
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


async def main() -> int:
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
                    page = ctx.pages[0] if ctx.pages else await ctx.new_page()
                    ua = await page.evaluate("navigator.userAgent")
                    ok = report({
                        "phase": "success",
                        "auth_token": jar["auth_token"],
                        "ct0": jar["ct0"],
                        "cookies": jar_cookies,
                        "user_agent": ua,
                        "x_user_id": extract_user_id(jar_cookies),
                    })
                    return 0 if ok else 2
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
