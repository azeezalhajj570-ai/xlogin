"""Runs inside the disposable login container.

Opens X's login page in a real, visible Chromium (on the Xvfb display the
subscriber sees through noVNC). The person completes login + any 2FA / captcha /
email code themselves. As soon as the `auth_token` and `ct0` cookies exist, the
cookies are posted to the service's callback and the container exits.

This is a real browser the user drives — there is no automation of the login
itself and no attempt to disguise the browser.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import urllib.parse
import urllib.request

from playwright.async_api import async_playwright

SID = os.environ["XLOGIN_SESSION_ID"]
CALLBACK_URL = os.environ["XLOGIN_CALLBACK_URL"]
CALLBACK_TOKEN = os.environ["XLOGIN_CALLBACK_TOKEN"]
TIMEOUT = int(os.getenv("XLOGIN_LOGIN_TIMEOUT", "900"))
PREFILL_USER = os.getenv("XLOGIN_PREFILL_USER", "").strip()
PROXY_URL = os.getenv("XLOGIN_PROXY_URL", "").strip()
PROFILE_DIR = "/profile" if os.path.isdir("/profile") else "/tmp/profile"


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


def parse_proxy(url: str):
    if not url:
        return None
    p = urllib.parse.urlparse(url)
    proxy = {"server": f"{p.scheme}://{p.hostname}:{p.port}"}
    if p.username:
        proxy["username"] = urllib.parse.unquote(p.username)
        proxy["password"] = urllib.parse.unquote(p.password or "")
    return proxy


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
    # profile the next launch finds a foreign lock and exits immediately
    # ("Target page, context or browser has been closed"). Remove them first;
    # only this container uses this profile right now.
    for name in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
        try:
            os.unlink(os.path.join(PROFILE_DIR, name))
        except OSError:
            pass


async def main() -> int:
    clear_stale_singleton_locks()
    async with async_playwright() as pw:
        ctx = await pw.chromium.launch_persistent_context(
            user_data_dir=PROFILE_DIR,
            headless=False,
            proxy=parse_proxy(PROXY_URL),
            viewport=None,
            no_viewport=True,
            # The human drives the login, so don't let Chromium advertise
            # itself as automation: drop --enable-automation (which sets
            # navigator.webdriver=true) and the AutomationControlled flag.
            ignore_default_args=["--enable-automation"],
            args=[
                "--start-maximized",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
            ],
        )
        page = ctx.pages[0] if ctx.pages else await ctx.new_page()

        # Already have a valid session from a saved profile? Finish immediately.
        await page.goto("https://x.com/home", wait_until="domcontentloaded")
        if not await _has_cookies(ctx):
            await page.goto("https://x.com/i/flow/login", wait_until="domcontentloaded")
            if PREFILL_USER:
                try:
                    field = page.locator('input[autocomplete="username"]')
                    await field.wait_for(timeout=15_000)
                    await field.fill(PREFILL_USER)
                except Exception:
                    pass  # the user can type it themselves

        report({"phase": "ready"})

        loop = asyncio.get_event_loop()
        deadline = loop.time() + TIMEOUT
        while loop.time() < deadline:
            if await _has_cookies(ctx):
                await asyncio.sleep(2)  # let X finish setting ct0/twid
                cookies = await ctx.cookies(["https://x.com", "https://twitter.com"])
                jar = {c["name"]: c["value"] for c in cookies}
                if jar.get("auth_token") and jar.get("ct0"):
                    ua = await page.evaluate("navigator.userAgent")
                    ok = report({
                        "phase": "success",
                        "auth_token": jar["auth_token"],
                        "ct0": jar["ct0"],
                        "cookies": cookies,
                        "user_agent": ua,
                        "x_user_id": extract_user_id(cookies),
                    })
                    await ctx.close()
                    return 0 if ok else 2
            await asyncio.sleep(2)

        report({"phase": "timeout"})
        await ctx.close()
        return 1


async def _has_cookies(ctx) -> bool:
    jar = {c["name"]: c["value"] for c in await ctx.cookies(["https://x.com", "https://twitter.com"])}
    return bool(jar.get("auth_token") and jar.get("ct0"))


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception as e:  # noqa: BLE001
        print(f"fatal: {e}", file=sys.stderr, flush=True)
        report({"phase": "failed", "error": str(e)})
        sys.exit(3)
