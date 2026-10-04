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
class NodeConfig:
    """One browser server: a Docker endpoint the orchestrator may place
    browser containers on. Capacity is counted in slots (1 slot = 1 Chrome,
    interactive logins included)."""
    name: str
    docker_host: str
    slots: int = 50
    # Private IP of the node. When set, each container's VNC port is published
    # on this IP only (random host port) so the control plane can reach a
    # container on another machine. When empty, the control plane reaches the
    # container by name on the shared Docker network (single-host setup).
    address: str = ""
    network: str = ""               # Docker network for containers on this node
    callback_base_url: str = ""     # how containers on this node reach the control plane


def _parse_nodes(default_docker: str, default_network: str, default_callback: str) -> tuple[NodeConfig, ...]:
    """XLOGIN_NODES=b1,b2 with XLOGIN_NODE_<NAME>_{DOCKER,SLOTS,ADDRESS,NETWORK,CALLBACK_BASE_URL}.
    Without XLOGIN_NODES there is one node, "local", on DOCKER_HOST."""
    names = [n.strip() for n in os.getenv("XLOGIN_NODES", "").split(",") if n.strip()]
    if not names:
        return (NodeConfig(name="local", docker_host=default_docker,
                           slots=int(os.getenv("XLOGIN_NODE_LOCAL_SLOTS", "50")),
                           network=default_network, callback_base_url=default_callback),)
    nodes = []
    for name in names:
        key = "XLOGIN_NODE_" + "".join(c if c.isalnum() else "_" for c in name).upper() + "_"
        address = os.getenv(key + "ADDRESS", "").strip()
        nodes.append(NodeConfig(
            name=name,
            docker_host=os.getenv(key + "DOCKER", "").strip() or default_docker,
            slots=int(os.getenv(key + "SLOTS", "2")),
            address=address,
            # A remote node publishes VNC on its private IP, so its containers
            # use the node's default bridge network unless told otherwise.
            network=os.getenv(key + "NETWORK", "").strip() or ("bridge" if address else default_network),
            callback_base_url=(os.getenv(key + "CALLBACK_BASE_URL", "").strip() or default_callback).rstrip("/"),
        ))
    return tuple(nodes)


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
    # ---- persistent browsers (keep the account's Chrome open after login) ----
    keep_alive: bool = False        # off = the original capture-and-destroy behaviour
    browser_memory: int = 1024**3   # memory cap of a live browser (logins use container_memory)
    browser_idle: int = 0           # seconds without use before a live browser sleeps; 0 = never
    keeper_poll: int = 90           # seconds between keeper checks (jittered ±20% in the container)
    keeper_touch: int = 14400       # seconds between reloads of x.com/home (jittered)
    browser_restart_max: int = 5    # restarts after missed heartbeats before giving up
    refresh_webhook_interval: int = 60  # at most one session.refreshed per account per this many seconds
    # Set no-new-privileges on browser containers. Needs Docker CE: the snap
    # build of Docker rejects it, so it stays opt-in for existing hosts.
    no_new_privileges: bool = False
    # Virtual screen of the remote browser (WIDTHxHEIGHTxDEPTH). "mobile" is a
    # portrait screen so the login is readable and tappable on a phone. An
    # account keeps the screen it logged in with across wakes and restarts, so
    # its browser fingerprint stays the same.
    desktop_screen: str = "1440x900x24"
    mobile_screen: str = "400x760x24"
    nodes: tuple[NodeConfig, ...] = ()

    def screen_for(self, device: str | None) -> str:
        return self.mobile_screen if device == "mobile" else self.desktop_screen

    def node(self, name: str) -> NodeConfig | None:
        return next((n for n in self.all_nodes() if n.name == name), None)

    def all_nodes(self) -> tuple[NodeConfig, ...]:
        if self.nodes:
            return self.nodes
        return (NodeConfig(name="local", docker_host=self.docker_host, slots=50,
                           network=self.browser_network, callback_base_url=self.callback_base_url),)

    @property
    def default_node(self) -> str:
        return self.all_nodes()[0].name

    @property
    def heartbeat_timeout(self) -> int:
        """Seconds without a heartbeat before a live browser counts as crashed."""
        return max(3 * self.keeper_poll, 90)

    @classmethod
    def from_env(cls) -> "Settings":
        docker_host = os.getenv("DOCKER_HOST", cls.docker_host)
        browser_network = os.getenv("XLOGIN_BROWSER_NETWORK", cls.browser_network)
        callback_base_url = os.getenv("XLOGIN_CALLBACK_BASE_URL", "http://xlogin:8000").rstrip("/")
        s = cls(
            api_keys=_list("XLOGIN_API_KEYS"),
            encryption_keys=_list("XLOGIN_ENCRYPTION_KEYS"),
            public_base_url=_req("XLOGIN_PUBLIC_BASE_URL").rstrip("/"),
            callback_base_url=callback_base_url,
            database_path=os.getenv("XLOGIN_DATABASE_PATH", cls.database_path),
            docker_host=docker_host,
            docker_api_version=os.getenv("XLOGIN_DOCKER_API_VERSION", cls.docker_api_version),
            browser_image=os.getenv("XLOGIN_BROWSER_IMAGE", cls.browser_image),
            browser_network=browser_network,
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
            keep_alive=_bool("XLOGIN_KEEP_ALIVE", cls.keep_alive),
            browser_memory=_bytes(os.getenv("XLOGIN_BROWSER_MEMORY", "1g")),
            browser_idle=int(os.getenv("XLOGIN_BROWSER_IDLE", cls.browser_idle)),
            keeper_poll=int(os.getenv("XLOGIN_KEEPER_POLL", cls.keeper_poll)),
            keeper_touch=int(os.getenv("XLOGIN_KEEPER_TOUCH", cls.keeper_touch)),
            browser_restart_max=int(os.getenv("XLOGIN_BROWSER_RESTART_MAX", cls.browser_restart_max)),
            no_new_privileges=_bool("XLOGIN_NO_NEW_PRIVILEGES", cls.no_new_privileges),
            desktop_screen=os.getenv("XLOGIN_DESKTOP_SCREEN", cls.desktop_screen),
            mobile_screen=os.getenv("XLOGIN_MOBILE_SCREEN", cls.mobile_screen),
            nodes=_parse_nodes(docker_host, browser_network, callback_base_url),
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
        if not 30 <= self.keeper_poll <= 3600:
            raise ConfigError("XLOGIN_KEEPER_POLL must be between 30 and 3600 seconds")
        if self.keeper_touch < 600:
            raise ConfigError("XLOGIN_KEEPER_TOUCH must be at least 600 seconds")
        if self.browser_memory < 512 * 1024**2:
            raise ConfigError("XLOGIN_BROWSER_MEMORY must be at least 512m")
        if self.browser_idle < 0:
            raise ConfigError("XLOGIN_BROWSER_IDLE must be 0 (never) or a positive number of seconds")
        import re
        for var, val in (("XLOGIN_DESKTOP_SCREEN", self.desktop_screen), ("XLOGIN_MOBILE_SCREEN", self.mobile_screen)):
            if not re.fullmatch(r"\d{3,4}x\d{3,4}x(16|24)", val):
                raise ConfigError(f"{var} must look like 1440x900x24")
        names = [n.name for n in self.all_nodes()]
        if len(set(names)) != len(names):
            raise ConfigError("XLOGIN_NODES contains a duplicate name")
        for n in self.all_nodes():
            if n.slots < 1:
                raise ConfigError(f"node {n.name}: slots must be at least 1")
