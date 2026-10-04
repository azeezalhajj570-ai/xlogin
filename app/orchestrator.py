"""Creates and removes the hardened browser containers, on one or more nodes.

A node is a Docker endpoint (normally a docker-socket-proxy) on a browser
server. Two kinds of container run there:

  * login   - an interactive login the account owner drives over VNC. With
              keep-alive on, it stays running after the cookies are captured
              and becomes the account's live browser.
  * browser - started later on the account's saved profile (wake / restart /
              move), with no login page.

The profile volume of an account lives on one node, so an account stays on its
node until it is moved with `copy_profile`.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from .config import NodeConfig, Settings
from .docker_api import DockerClient

log = logging.getLogger("xlogin.orchestrator")

MANAGED_LABEL = "xlogin.managed"


def profile_volume_name(account_id: str) -> str:
    return "xlogin-profile-" + hashlib.sha256(account_id.encode()).hexdigest()[:24]


@dataclass(frozen=True)
class Started:
    name: str
    vnc_host: str
    vnc_port: int


@dataclass(frozen=True)
class Managed:
    name: str
    session_id: str
    node: str
    kind: str          # "login" | "browser"
    run_id: str


class Orchestrator:
    def __init__(self, docker: DockerClient | dict[str, DockerClient] | None, settings: Settings):
        self.s = settings
        self.nodes: dict[str, NodeConfig] = {n.name: n for n in settings.all_nodes()}
        if isinstance(docker, dict):
            self.docker = docker
        else:
            # One client per node; the first node may reuse a client passed in.
            self.docker = {}
            for i, n in enumerate(settings.all_nodes()):
                if i == 0 and docker is not None:
                    self.docker[n.name] = docker
                else:
                    self.docker[n.name] = DockerClient(n.docker_host, settings.docker_api_version)
        self._seccomp = self._load_seccomp(settings.browser_seccomp_path)

    @staticmethod
    def _load_seccomp(path: str) -> str | None:
        """Read the seccomp profile that lets Chrome's sandbox start under
        CapDrop:ALL. The Docker Engine API wants the profile *inlined* as a JSON
        string in SecurityOpt (unlike the CLI, which reads a file path). Returns
        None if unavailable, in which case Chrome falls back to --no-sandbox."""
        if not path:
            return None
        try:
            with open(path, encoding="utf-8") as f:
                content = f.read()
            if content.strip():
                return content
            log.warning("seccomp profile %s is empty; Chrome will run --no-sandbox", path)
        except OSError as e:
            log.warning("seccomp profile %s unreadable (%s); Chrome will run --no-sandbox", path, e)
        return None

    # ---- nodes ------------------------------------------------------------
    def node_names(self) -> list[str]:
        return list(self.nodes)

    def slots(self, node: str) -> int:
        return self.nodes[node].slots

    def callback_base_url(self, node: str) -> str:
        return self.nodes[node].callback_base_url or self.s.callback_base_url

    def ping(self) -> bool:
        return all(self.ping_node(n) for n in self.nodes)

    def ping_node(self, node: str) -> bool:
        try:
            return self.docker[node].ping()
        except Exception:  # noqa: BLE001
            return False

    # ---- containers -------------------------------------------------------
    def start(self, session_id: str, account_id: str, env: dict[str, str], node: str | None = None,
              kind: str = "login", run_id: str | None = None, memory: int | None = None) -> Started:
        node = node or self.s.default_node
        cfg = self.nodes[node]
        run_id = run_id or session_id
        name = f"xlogin-{session_id[:12]}" if kind == "login" else f"xlogin-b-{run_id[:12]}"
        mounts = []
        if self.s.persist_profiles:
            mounts.append({"Type": "volume", "Source": profile_volume_name(account_id), "Target": "/profile"})
        env = dict(env)
        # Chrome's own sandbox needs user namespaces, which CapDrop:ALL + the
        # default seccomp profile would otherwise block. Apply the extended
        # profile when we have it; without it, tell the browser to run
        # --no-sandbox so it still starts (at the cost of the sandbox + a visible
        # infobar). Keeping the sandbox on is preferred - the banner is a signal
        # to anti-bot systems.
        security_opt: list[str] = []
        if self.s.no_new_privileges:
            # Off by default: the snap-packaged Docker daemon rejects containers
            # that set no_new_privs ("exec ... operation not permitted"). Turn it
            # on (XLOGIN_NO_NEW_PRIVILEGES=1) on hosts running Docker CE.
            security_opt.append("no-new-privileges:true")
        if self._seccomp:
            security_opt.append("seccomp=" + self._seccomp)
        else:
            env["XLOGIN_CHROME_NO_SANDBOX"] = "1"
        mem = memory or self.s.container_memory
        host_config = {
            "AutoRemove": True,
            "NetworkMode": cfg.network or self.s.browser_network,
            "Memory": mem,
            "MemorySwap": mem,
            "NanoCpus": int(self.s.container_cpus * 1e9),
            "PidsLimit": self.s.container_pids,
            "ShmSize": 512 * 1024**2,
            "ReadonlyRootfs": True,
            "Tmpfs": {"/tmp": "rw,nosuid,nodev,size=768m"},
            "CapDrop": ["ALL"],
            "SecurityOpt": security_opt,
            "Mounts": mounts,
            "LogConfig": {"Type": "json-file", "Config": {"max-size": "5m", "max-file": "1"}},
        }
        config = {
            "Image": self.s.browser_image,
            "Env": [f"{k}={v}" for k, v in env.items() if v is not None],
            "Labels": {MANAGED_LABEL: "true", "xlogin.session": session_id if kind == "login" else "",
                       "xlogin.kind": kind, "xlogin.run": run_id, "xlogin.node": node},
            "HostConfig": host_config,
        }
        port_key = f"{self.s.vnc_port}/tcp"
        if cfg.address:
            # Remote node: publish VNC on the node's private IP only, on a random
            # host port, so the control plane can reach it over the private network.
            config["ExposedPorts"] = {port_key: {}}
            host_config["PortBindings"] = {port_key: [{"HostIp": cfg.address, "HostPort": ""}]}
        docker = self.docker[node]
        cid = docker.create_container(name, config)
        try:
            docker.start_container(cid)
        except Exception:
            docker.remove_container(cid)
            raise
        vnc_host, vnc_port = name, self.s.vnc_port
        if cfg.address:
            info = docker.inspect_container(cid)
            binding = ((info.get("NetworkSettings") or {}).get("Ports") or {}).get(port_key) or []
            if not binding:
                docker.remove_container(cid)
                raise RuntimeError("VNC port was not published")
            vnc_host, vnc_port = cfg.address, int(binding[0]["HostPort"])
        log.info("started %s container %s on node %s", kind, name, node)
        return Started(name=name, vnc_host=vnc_host, vnc_port=vnc_port)

    def stop(self, container_name: str | None, node: str | None = None) -> None:
        if not container_name:
            return
        targets = [node] if node in self.docker else list(self.docker)
        for n in targets:
            try:
                self.docker[n].remove_container(container_name)
            except Exception:  # noqa: BLE001
                log.warning("could not remove %s on node %s", container_name, n)

    def set_memory(self, container_name: str, node: str, memory: int) -> None:
        """Best effort, once a login container becomes a background browser:
        set a *soft* limit (MemoryReservation). Lowering the hard limit below
        what Chrome is already using would get it OOM-killed right after a
        successful login; a reservation only makes the kernel reclaim towards it
        under memory pressure. Browsers started later (wake / restart / move)
        get `browser_memory` as their hard limit from the start."""
        if memory >= self.s.container_memory:
            return
        try:
            self.docker[node].update_container(container_name, {"MemoryReservation": memory})
        except Exception as e:  # noqa: BLE001
            log.warning("could not set memory reservation of %s: %s", container_name, e)

    def managed_containers(self) -> list[Managed]:
        """Every container this service owns, on every reachable node."""
        out = []
        for node, docker in self.docker.items():
            try:
                rows = docker.list_containers(f"{MANAGED_LABEL}=true")
            except Exception:  # noqa: BLE001
                log.warning("node %s unreachable while listing containers", node)
                continue
            for c in rows:
                labels = c.get("Labels") or {}
                name = (c.get("Names") or ["?"])[0].lstrip("/")
                sid = labels.get("xlogin.session", "")
                out.append(Managed(name=name, session_id=sid, node=labels.get("xlogin.node", node),
                                   kind=labels.get("xlogin.kind", "login"),
                                   run_id=labels.get("xlogin.run", sid)))
        return out

    # ---- profiles ---------------------------------------------------------
    def delete_profile(self, account_id: str, node: str | None = None) -> None:
        for n in ([node] if node in self.docker else list(self.docker)):
            self.docker[n].remove_volume(profile_volume_name(account_id))

    def copy_profile(self, account_id: str, src: str, dst: str) -> None:
        """Copy an account's profile volume between nodes through the Docker API
        (no shell access to either node). Helper containers are created but never
        started; the archive endpoints work on stopped containers."""
        vol = profile_volume_name(account_id)
        tag = hashlib.sha256(account_id.encode()).hexdigest()[:12]

        def helper(node: str, name: str, target: str) -> str:
            return self.docker[node].create_container(name, {
                "Image": self.s.browser_image,
                "Cmd": ["true"],
                "Labels": {MANAGED_LABEL: "true", "xlogin.kind": "helper"},
                "HostConfig": {"Mounts": [{"Type": "volume", "Source": vol, "Target": target}]},
            })

        src_id = helper(src, f"xlogin-copy-src-{tag}", "/profile")
        try:
            tar = self.docker[src].get_archive(src_id, "/profile")
        finally:
            self.docker[src].remove_container(src_id)
        # The tar's top entry is "profile/", so extract it at "/" on a helper
        # that mounts the destination volume at /profile.
        dst_id = helper(dst, f"xlogin-copy-dst-{tag}", "/profile")
        try:
            self.docker[dst].put_archive(dst_id, "/", tar)
        finally:
            self.docker[dst].remove_container(dst_id)
        log.info("copied profile of %s from %s to %s (%d bytes)", account_id, src, dst, len(tar))
