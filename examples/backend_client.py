"""Example: how YOUR backend talks to the xlogin service.

When a subscriber clicks "Connect X account", call start_login() and redirect
them (or open a popup) to the returned login_url. Poll get_session() or listen
for the `login.succeeded` webhook, then read the cookies with get_credentials()
and hand them to your automation workers.
"""
from __future__ import annotations

import os
import urllib.request
import json

XLOGIN = os.getenv("XLOGIN_BASE", "https://xlogin.example.com")
API_KEY = os.environ["XLOGIN_API_KEY"]


def _call(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(XLOGIN + path, data=data, method=method, headers={
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b"{}")


def start_login(account_id: str, username: str | None = None,
                expected_user_id: str | None = None, proxy_url: str | None = None) -> dict:
    """Returns {session_id, status, login_url, expires_in}. Send the user to login_url."""
    return _call("POST", "/sessions", {
        "account_id": account_id,
        "username": username,
        "expected_user_id": expected_user_id,
        "proxy_url": proxy_url,
    })


def get_session(account_id: str, session_id: str) -> dict:
    return _call("GET", f"/sessions/{session_id}?account_id={account_id}")


def cancel_login(account_id: str, session_id: str) -> dict:
    return _call("DELETE", f"/sessions/{session_id}?account_id={account_id}")


def get_credentials(account_id: str) -> dict:
    """Returns {auth_token, ct0, cookies, user_agent, x_user_id, captured_at}."""
    return _call("GET", f"/accounts/{account_id}/credentials")


def disconnect(account_id: str) -> dict:
    """Wipe stored cookies + the saved browser profile for an account."""
    return _call("DELETE", f"/accounts/{account_id}")


if __name__ == "__main__":
    import sys, time
    acc = sys.argv[1] if len(sys.argv) > 1 else "demo-account"
    s = start_login(acc, username=sys.argv[2] if len(sys.argv) > 2 else None)
    print("Send the subscriber here:\n ", s["login_url"])
    print("Waiting for them to finish...")
    while True:
        time.sleep(3)
        st = get_session(acc, s["session_id"])
        print(" status:", st["status"])
        if st["status"] in ("success", "failed", "timeout", "cancelled"):
            break
    if st["status"] == "success":
        creds = get_credentials(acc)
        print("Captured auth_token (first 6):", creds["auth_token"][:6] + "…", "x_user_id:", creds["x_user_id"])
