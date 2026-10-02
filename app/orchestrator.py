"""Creates and removes the disposable, hardened login-browser containers."""
from __future__ import annotations

import hashlib
import logging

from .config import Settings
from .docker_api import DockerClient

log = logging.getLogger("xlogin.orchestrator")

MANAGED_LABEL = "xlogin.managed"


def profile_volume_name(account_id: str) -> str:
    return "xlogin-profile-" + hashlib.sha256(account_id.encode()).hexdigest()[:24]


class Orchestrator:
    def __init__(self, docker: DockerClient, settings: Settings):
        self.docker = docker
        self.s = settings

    def ping(self) -> bool:
        return self.docker.ping()

    def start(self, session_id: str, account_id: str, env: dict[str, str]) -> str:
        name = f"xlogin-{session_id[:12]}"
        mounts = []
        if self.s.persist_profiles:
            mounts.append({"Type": "volume", "Source": profile_volume_name(account_id), "Target": "/profile"})
        config = {
            "Image": self.s.browser_image,
            "Env": [f"{k}={v}" for k, v in env.items() if v is not None],
            "Labels": {MANAGED_LABEL: "true", "xlogin.session": session_id},
            "HostConfig": {
                "AutoRemove": True,
                "NetworkMode": self.s.browser_network,
                "Memory": self.s.container_memory,
                "MemorySwap": self.s.container_memory,
                "NanoCpus": int(self.s.container_cpus * 1e9),
                "PidsLimit": self.s.container_pids,
                "ShmSize": 512 * 1024**2,
                "ReadonlyRootfs": True,
                "Tmpfs": {"/tmp": "rw,nosuid,nodev,size=768m"},
                "CapDrop": ["ALL"],
                # NOTE: no-new-privileges intentionally omitted on this host.
                # The Docker daemon here is snap-packaged (Canonical), whose
                # snapd confinement rejects containers that set no_new_privs
                # ("exec ... operation not permitted"). CapDrop ALL + read-only
                # rootfs + non-root user still apply. Restore this on a host
                # running apt/official Docker CE:
                #     "SecurityOpt": ["no-new-privileges:true"],
                "SecurityOpt": [],
                "Mounts": mounts,
                "LogConfig": {"Type": "json-file", "Config": {"max-size": "5m", "max-file": "1"}},
            },
        }
        cid = self.docker.create_container(name, config)
        try:
            self.docker.start_container(cid)
        except Exception:
            self.docker.remove_container(cid)
            raise
        log.info("started container %s for session %s", name, session_id)
        return name

    def stop(self, container_name: str | None) -> None:
        if container_name:
            self.docker.remove_container(container_name)

    def managed_containers(self) -> list[tuple[str, str]]:
        """[(container_name, session_id)] for every container this service owns."""
        out = []
        for c in self.docker.list_containers(f"{MANAGED_LABEL}=true"):
            name = (c.get("Names") or ["?"])[0].lstrip("/")
            out.append((name, (c.get("Labels") or {}).get("xlogin.session", "")))
        return out

    def delete_profile(self, account_id: str) -> None:
        self.docker.remove_volume(profile_volume_name(account_id))
