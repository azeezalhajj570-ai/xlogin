"""Example webhook receiver (verify the HMAC signature before trusting it).

Mount this in your backend. On `login.succeeded`, call the credentials endpoint
to fetch the cookies (they are never included in the webhook payload).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time

SECRET = os.environ["XLOGIN_WEBHOOK_SECRET"].encode()
MAX_SKEW = 300  # reject replays older than 5 minutes


def verify(raw_body: bytes, timestamp: str, signature: str) -> bool:
    if abs(time.time() - int(timestamp)) > MAX_SKEW:
        return False
    expected = "sha256=" + hmac.new(SECRET, timestamp.encode() + b"." + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


# --- Flask flavour -----------------------------------------------------------
def flask_app():
    from flask import Flask, request, abort
    app = Flask(__name__)

    @app.post("/internal/xlogin/webhook")
    def hook():
        raw = request.get_data()
        if not verify(raw, request.headers.get("X-XLogin-Timestamp", "0"),
                      request.headers.get("X-XLogin-Signature", "")):
            abort(401)
        event = json.loads(raw)
        if event["event"] == "login.succeeded":
            acc = event["data"]["account_id"]
            # from examples.backend_client import get_credentials
            # creds = get_credentials(acc); store/queue automation for `acc`
            print("account connected:", acc)
        return "", 204

    return app


if __name__ == "__main__":
    flask_app().run(port=9000)
