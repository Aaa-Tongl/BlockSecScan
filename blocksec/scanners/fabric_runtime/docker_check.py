"""Docker SDK interactions for Fabric runtime scanning."""

import docker
from docker.models.containers import Container

FABRIC_IMAGE_KEYWORDS = ["fabric", "hyperledger", "peer", "orderer", "couchdb", "ca"]
SENSITIVE_MOUNT_PATHS = ["/var/run/docker.sock", "/etc", "/root", "/var/run", "/proc", "/sys"]


def get_docker_client() -> docker.DockerClient | None:
    try:
        return docker.from_env()
    except docker.errors.DockerException:
        return None


def get_fabric_containers(client: docker.DockerClient | None = None) -> list[Container]:
    if client is None:
        client = get_docker_client()
    if client is None:
        return []

    fabric_containers: list[Container] = []
    for container in client.containers.list():
        image_tags = container.image.tags or []
        image_name = " ".join(image_tags).lower()
        if any(kw in image_name for kw in FABRIC_IMAGE_KEYWORDS):
            fabric_containers.append(container)

    return fabric_containers


def check_container_root(container: Container) -> bool:
    """Return True if the container runs as root (UID 0)."""
    attrs = container.attrs
    config = attrs.get("Config", {})
    user = config.get("User", "")
    return bool(not user or user in ("root", "0", "0:0"))


def check_ports_exposed(container: Container) -> list[dict]:
    """Return list of ports bound to 0.0.0.0 (all interfaces)."""
    exposed: list[dict] = []
    ports = container.attrs.get("NetworkSettings", {}).get("Ports", {}) or {}
    for container_port, bindings in ports.items():
        if bindings is None:
            continue
        for binding in bindings:
            host_ip = binding.get("HostIp", "")
            if host_ip == "0.0.0.0" or host_ip == "":
                exposed.append({
                    "container_port": container_port,
                    "host_ip": host_ip or "0.0.0.0",
                    "host_port": binding.get("HostPort", ""),
                })
    return exposed


def check_sensitive_mounts(container: Container) -> list[dict]:
    """Return list of sensitive host directory mounts."""
    mounts = container.attrs.get("Mounts", []) or []
    sensitive: list[dict] = []
    for mount in mounts:
        source = mount.get("Source", "")
        for sensitive_path in SENSITIVE_MOUNT_PATHS:
            if source.startswith(sensitive_path):
                sensitive.append({
                    "source": source,
                    "destination": mount.get("Destination", ""),
                    "mode": mount.get("Mode", ""),
                })
                break
    return sensitive


def check_container_env(container: Container) -> list[dict]:
    """Check container environment variables for security issues."""
    issues: list[dict] = []
    env_vars = container.attrs.get("Config", {}).get("Env", []) or []
    for var in env_vars:
        upper = var.upper()
        if "FABRIC_LOGGING_SPEC" in upper and "DEBUG" in upper:
            issues.append({"var": var, "issue": "DEBUG logging enabled"})
        if "CORE_PEER_TLS_ENABLED" in upper and "FALSE" in upper:
            issues.append({"var": var, "issue": "TLS disabled"})
        if "ORDERER_GENERAL_TLS_ENABLED" in upper and "FALSE" in upper:
            issues.append({"var": var, "issue": "Orderer TLS disabled"})
    return issues
