"""Encryption at rest (Fernet, with key rotation) and token helpers."""
from __future__ import annotations

import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet, MultiFernet


class SecretBox:
    """Encrypts/decrypts strings. The first key encrypts; all keys can decrypt,
    so you can rotate by prepending a new key and later calling `rotate`."""

    def __init__(self, keys: tuple[str, ...] | list[str]):
        if not keys:
            raise ValueError("at least one encryption key is required")
        self._f = MultiFernet([Fernet(k.encode()) for k in keys])

    def encrypt(self, value: str | None) -> str | None:
        if value is None:
            return None
        return self._f.encrypt(value.encode()).decode()

    def decrypt(self, token: str | None) -> str | None:
        if token is None:
            return None
        return self._f.decrypt(token.encode()).decode()

    def rotate(self, token: str | None) -> str | None:
        if token is None:
            return None
        return self._f.rotate(token.encode()).decode()


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def new_vnc_password() -> str:
    # RFB/VNC auth only uses the first 8 characters.
    alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(8))


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def safe_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def sign_webhook(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()
