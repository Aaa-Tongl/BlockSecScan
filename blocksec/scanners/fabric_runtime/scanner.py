"""Fabric 运行时安全扫描器。

检测正在运行的 Fabric 环境：
- Docker 容器安全（root/privileged/敏感挂载/网络模式）
- CouchDB 可访问性
- 证书有效期
- 端口暴露情况
"""

from blocksec.models.finding import Category, Finding
from blocksec.scanners.base import BaseScanner
from blocksec.scanners.fabric_runtime.cert_check import CertCheck
from blocksec.scanners.fabric_runtime.couchdb_check import CouchDBCheck
from blocksec.scanners.fabric_runtime.docker_check import DockerCheck


class FabricRuntimeScanner(BaseScanner):
    name = "fabric_runtime"
    description = "Hyperledger Fabric 运行时安全扫描器"

    def __init__(self):
        self._docker_check = DockerCheck()
        self._couchdb_check = CouchDBCheck()
        self._cert_check = CertCheck()

    def can_handle(self, target_type: str) -> bool:
        return target_type in ("fabric_runtime",)

    def scan(self, target_path: str) -> list[Finding]:
        findings: list[Finding] = []

        findings.extend(self._docker_check.check_all_containers())

        findings.extend(self._scan_ports())

        findings.extend(self._scan_certs(target_path))

        for f in findings:
            f.category = Category.FABRIC_RUNTIME

        return findings

    def _scan_ports(self) -> list[Finding]:
        findings: list[Finding] = []

        findings.extend(self._couchdb_check.check_port("127.0.0.1", 5984))
        findings.extend(self._couchdb_check.check_port("127.0.0.1", 7051))
        findings.extend(self._couchdb_check.check_port("127.0.0.1", 7050))

        return findings

    def _scan_certs(self, target_path: str) -> list[Finding]:
        return self._cert_check.scan_directory(target_path)
