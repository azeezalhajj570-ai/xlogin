"""Settings, loaded once from environment variables. See .env.example."""
from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse


class ConfigError(RuntimeError):
    pass


def _req(name: str) -> str:
    val = os.getenv(name, "").strip()
    if not val:
        raise ConfigError(f"{name} is required")
    return val


def _list(name: str) -> tuple[str, ...]:
    return tuple(v.strip() for v in _req(name).split(",") if v.strip())


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _bytes(value: str) -> int:
    value = value.strip().lower()
    units = {"k": 1024, "m": 1024**2, "g": 1024**3}
    if value[-1] in units:
        return int(float(value[:-1]) * units[value[-1]])
    return int(value)


@dataclass(frozen=True)
class Settings:
    api_keys: tuple[str, ...]
    encryption_keys: tuple[str, ...]
    public_base_url: str            # what operators' browsers use, e.g. https://xlogin.example.com
    callback_base_url: str          # what login containers use to reach this service
    database_path: str = "/data/xlogin.db"
    docker_host: str = "unix:///var/run/docker.sock"
    docker_api_version: str = "v1.43"
    browser_image: str = "xlogin-browser:latest"
    browser_network: str = "xlogin-browsers"
    vnc_port: int = 5900
    max_sessions: int = 3
    session_ttl: int = 900          # seconds an operator has to finish logging in
    start_timeout: int = 120        # seconds for the browser container to report "ready"
    persist_profiles: bool = True   # keep a browser profile per account (fewer 2FA / new-device prompts)
    container_memory: int = 1536 * 1024**2
    container_cpus: float = 1.0
    container_pids: int = 512
    webhook_url: str | None = None
    webhook_secret: str | None = None
    novnc_dir: str = "/opt/novnc"
    session_retention_days: int = 30
    reaper_interval: int = 15
    # Seccomp profile for login-browser containers (Docker's default plus the
    # syscalls Chrome's user-namespace sandbox needs). Empty disables it, which
    # forces Chrome to run with --no-sandbox — see Orchestrator.
    browser_seccomp_path: str = "/srv/seccomp-chrome.json"

    @classmethod
    def from_env(cls) -> "Settings":
        s = cls(
            api_keys=_list("XLOGIN_API_KEYS"),
            encryption_keys=_list("XLOGIN_ENCRYPTION_KEYS"),
            public_base_url=_req("XLOGIN_PUBLIC_BASE_URL").rstrip("/"),
            callback_base_url=os.getenv("XLOGIN_CALLBACK_BASE_URL", "http://xlogin:8000").rstrip("/"),
            database_path=os.getenv("XLOGIN_DATABASE_PATH", cls.database_path),
            docker_host=os.getenv("DOCKER_HOST", cls.docker_host),
            docker_api_version=os.getenv("XLOGIN_DOCKER_API_VERSION", cls.docker_api_version),
            browser_image=os.getenv("XLOGIN_BROWSER_IMAGE", cls.browser_image),
            browser_network=os.getenv("XLOGIN_BROWSER_NETWORK", cls.browser_network),
            max_sessions=int(os.getenv("XLOGIN_MAX_SESSIONS", cls.max_sessions)),
            session_ttl=int(os.getenv("XLOGIN_SESSION_TTL", cls.session_ttl)),
            start_timeout=int(os.getenv("XLOGIN_START_TIMEOUT", cls.start_timeout)),
            persist_profiles=_bool("XLOGIN_PERSIST_PROFILES", cls.persist_profiles),
            container_memory=_bytes(os.getenv("XLOGIN_CONTAINER_MEMORY", "1536m")),
            container_cpus=float(os.getenv("XLOGIN_CONTAINER_CPUS", cls.container_cpus)),
            container_pids=int(os.getenv("XLOGIN_CONTAINER_PIDS", cls.container_pids)),
            webhook_url=os.getenv("XLOGIN_WEBHOOK_URL") or None,
            webhook_secret=os.getenv("XLOGIN_WEBHOOK_SECRET") or None,
            novnc_dir=os.getenv("XLOGIN_NOVNC_DIR", cls.novnc_dir),
            session_retention_days=int(os.getenv("XLOGIN_SESSION_RETENTION_DAYS", cls.session_retention_days)),
            browser_seccomp_path=os.getenv("XLOGIN_BROWSER_SECCOMP_PATH", cls.browser_seccomp_path),
        )
        s.validate(allow_insecure=_bool("XLOGIN_ALLOW_INSECURE_HTTP", False))
        return s

    def validate(self, allow_insecure: bool = False) -> None:
        if any(len(k) < 32 for k in self.api_keys):
            raise ConfigError("every XLOGIN_API_KEYS entry must be at least 32 characters")
        if urlparse(self.public_base_url).scheme != "https" and not allow_insecure:
            raise ConfigError("XLOGIN_PUBLIC_BASE_URL must be https (set XLOGIN_ALLOW_INSECURE_HTTP=1 for local dev)")
        if self.webhook_url and not self.webhook_secret:
            raise ConfigError("XLOGIN_WEBHOOK_SECRET is required when XLOGIN_WEBHOOK_URL is set")
        if self.webhook_secret and len(self.webhook_secret) < 32:
            raise ConfigError("XLOGIN_WEBHOOK_SECRET must be at least 32 characters")
        if not 1 <= self.max_sessions <= 50:
            raise ConfigError("XLOGIN_MAX_SESSIONS must be between 1 and 50")
        if not 60 <= self.session_ttl <= 3600:
            raise ConfigError("XLOGIN_SESSION_TTL must be between 60 and 3600 seconds")
