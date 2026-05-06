"""Docker 容器安全检测模块。

检测项：
- 容器是否以 root 用户运行
- 容器是否启用 privileged 模式
- 容器是否挂载 Docker socket 等敏感目录
- 容器网络模式
"""

from __future__ import annotations

import docker
from docker.errors import DockerException

from blocksec.models.finding import Finding, FindingLocation, Severity


class DockerCheck:
    def __init__(self):
        self._client: docker.DockerClient | None = None
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        if self._available is None:
            try:
                self._client = docker.from_env()
                self._client.ping()
                self._available = True
            except DockerException:
                self._available = False
        return self._available

    def get_client(self) -> docker.DockerClient | None:
        if self.available:
            return self._client
        return None

    def check_all_containers(self) -> list[Finding]:
        if not self.available:
            return []

        findings: list[Finding] = []
        client = self._client
        if client is None:
            return findings

        try:
            containers = client.containers.list(all=False)
        except DockerException:
            return findings

        for container in containers:
            findings.extend(self.check_container_root(container))
            findings.extend(self.check_privileged(container))
            findings.extend(self.check_sensitive_mounts(container))
            findings.extend(self.check_network_mode(container))

        return findings

    def check_container_root(
        self,
        container: docker.models.containers.Container,
    ) -> list[Finding]:
        findings: list[Finding] = []
        attrs = container.attrs
        config = attrs.get("Config", {})
        user = config.get("User", "")

        if user == "" or user == "root" or user == "0" or user == "0:0":
            findings.append(
                Finding(
                    rule_id="FABRIC_RUNTIME_CONTAINER_ROOT",
                    severity=Severity.HIGH,
                    title=f"容器 {container.name} 以 root 用户运行",
                    description=(
                        f"容器 {container.name} 以 root 用户运行，存在容器逃逸和权限扩大风险。"
                        "攻击者若获取容器内代码执行权限，可能利用 root 权限进行横向移动或容器逃逸。"
                    ),
                    location=FindingLocation(
                        file_path=f"container://{container.name}", start_line=0, end_line=0
                    ),
                    evidence=f"Container '{container.name}' running as user: '{user or 'root (default)'}'",
                    remediation=f"在 Dockerfile 中使用 USER 指令切换到非 root 用户运行容器 '{container.name}'。",
                    references=[
                        "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"
                    ],
                    scanner_name="fabric_runtime",
                )
            )
        return findings

    def check_privileged(
        self,
        container: docker.models.containers.Container,
    ) -> list[Finding]:
        findings: list[Finding] = []
        attrs = container.attrs
        host_config = attrs.get("HostConfig", {})
        privileged = host_config.get("Privileged", False)

        if privileged:
            findings.append(
                Finding(
                    rule_id="FABRIC_RUNTIME_PRIVILEGED",
                    severity=Severity.CRITICAL,
                    title=f"容器 {container.name} 以特权模式运行",
                    description=(
                        f"容器 {container.name} 启用了 privileged 模式，容器拥有宿主机的所有内核能力，"
                        "这是极其危险的安全配置，攻击者可以轻易突破容器隔离。"
                    ),
                    location=FindingLocation(
                        file_path=f"container://{container.name}", start_line=0, end_line=0
                    ),
                    evidence=f"Container '{container.name}' is running in privileged mode",
                    remediation=f"移除容器 '{container.name}' 的 --privileged 标志，只授予必要的能力（--cap-add）。",
                    references=[
                        "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities"
                    ],
                    scanner_name="fabric_runtime",
                )
            )
        return findings

    def check_sensitive_mounts(
        self,
        container: docker.models.containers.Container,
    ) -> list[Finding]:
        findings: list[Finding] = []
        attrs = container.attrs
        mounts = attrs.get("Mounts", [])

        sensitive_paths = [
            "/var/run/docker.sock",
            "/proc",
            "/sys",
            "/etc/shadow",
            "/etc/passwd",
            "/root/.ssh",
        ]

        for mount in mounts:
            source = mount.get("Source", "")
            for sensitive in sensitive_paths:
                if source.startswith(sensitive) or sensitive.startswith(source):
                    severity = Severity.CRITICAL if "docker.sock" in source else Severity.HIGH
                    findings.append(
                        Finding(
                            rule_id="FABRIC_RUNTIME_SENSITIVE_MOUNT",
                            severity=severity,
                            title=f"容器 {container.name} 挂载了敏感目录 {source}",
                            description=(
                                f"容器 {container.name} 挂载了宿主机敏感路径 {source}。"
                                "这可能导致宿主机文件暴露或容器逃逸。"
                                + (
                                    " Docker socket 挂载意味着容器可以控制宿主机上所有容器。"
                                    if "docker.sock" in source
                                    else ""
                                )
                            ),
                            location=FindingLocation(
                                file_path=f"container://{container.name}", start_line=0, end_line=0
                            ),
                            evidence=(
                                f"Mount: {source} -> {mount.get('Destination', '')}"
                                f" in container '{container.name}'"
                            ),
                            remediation=f"移除容器 '{container.name}' 中不必要的敏感目录挂载。",
                            references=["https://docs.docker.com/engine/security/"],
                            scanner_name="fabric_runtime",
                        )
                    )
                    break
        return findings

    def check_network_mode(
        self,
        container: docker.models.containers.Container,
    ) -> list[Finding]:
        findings: list[Finding] = []
        attrs = container.attrs
        host_config = attrs.get("HostConfig", {})
        network_mode = host_config.get("NetworkMode", "default")

        if network_mode == "host":
            findings.append(
                Finding(
                    rule_id="FABRIC_RUNTIME_HOST_NETWORK",
                    severity=Severity.MEDIUM,
                    title=f"容器 {container.name} 使用 host 网络模式",
                    description=(
                        f"容器 {container.name} 使用 host 网络模式，容器与宿主机共享网络命名空间，"
                        "丧失了网络隔离保护。"
                    ),
                    location=FindingLocation(
                        file_path=f"container://{container.name}", start_line=0, end_line=0
                    ),
                    evidence=f"Container '{container.name}' network mode: host",
                    remediation=f"将容器 '{container.name}' 切换到 bridge 网络模式，只映射必要的端口。",
                    references=["https://docs.docker.com/network/host/"],
                    scanner_name="fabric_runtime",
                )
            )
        return findings
