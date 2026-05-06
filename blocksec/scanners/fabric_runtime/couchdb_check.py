"""CouchDB 可访问性检测模块。

通过 HTTP 请求实际检测 CouchDB 是否可访问（不入则只是配置扫描）。
"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request

from blocksec.models.finding import Finding, FindingLocation, Severity

COUCHDB_DEFAULT_PORT = 5984
CONNECT_TIMEOUT = 3
REQUEST_TIMEOUT = 5


class CouchDBCheck:
    def check_port(
        self, host: str = "127.0.0.1", port: int = COUCHDB_DEFAULT_PORT
    ) -> list[Finding]:
        findings: list[Finding] = []

        is_open = self._is_port_open(host, port)
        if not is_open:
            return findings

        accessible = self._is_couchdb_accessible(host, port)
        if accessible:
            findings.append(
                Finding(
                    rule_id="FABRIC_RUNTIME_COUCHDB_ACCESSIBLE",
                    severity=Severity.HIGH,
                    title=f"CouchDB 可通过 {host}:{port} 访问",
                    description=(
                        f"CouchDB 状态数据库在 {host}:{port} 可以 HTTP 访问。"
                        "攻击者可能直接查询或篡改账本数据。"
                    ),
                    location=FindingLocation(
                        file_path=f"http://{host}:{port}", start_line=0, end_line=0
                    ),
                    evidence=f"HTTP GET http://{host}:{port}/ 返回 CouchDB 响应",
                    remediation=(
                        f"配置 CouchDB 认证（用户名/密码），或使用防火墙限制 {port} 端口的访问来源。"
                        "生产环境建议 CouchDB 仅绑定 127.0.0.1。"
                    ),
                    references=[
                        "https://hyperledger-fabric.readthedocs.io/en/latest/couchdb_as_state_database.html",
                        "https://docs.couchdb.org/en/stable/config/auth.html",
                    ],
                    scanner_name="fabric_runtime",
                )
            )
        else:
            findings.append(
                Finding(
                    rule_id="FABRIC_RUNTIME_PORT_OPEN",
                    severity=Severity.MEDIUM,
                    title=f"端口 {host}:{port} 开放但非 CouchDB 服务",
                    description=f"端口 {host}:{port} 可连接，但未识别为 CouchDB 服务。",
                    location=FindingLocation(
                        file_path=f"tcp://{host}:{port}", start_line=0, end_line=0
                    ),
                    evidence=f"TCP connection to {host}:{port} succeeded",
                    remediation="确认该端口运行的服务是否符合预期，是否需要对外暴露。",
                    references=[],
                    scanner_name="fabric_runtime",
                    confidence=0.6,
                )
            )

        return findings

    def _is_port_open(self, host: str, port: int) -> bool:
        try:
            sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
            sock.close()
            return True
        except (TimeoutError, ConnectionRefusedError, OSError):
            return False

    def _is_couchdb_accessible(self, host: str, port: int) -> bool:
        try:
            url = f"http://{host}:{port}/"
            req = urllib.request.Request(url, method="GET")
            resp = urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT)
            body = resp.read(500).decode("utf-8", errors="replace")
            resp.close()
            return "couchdb" in body.lower() or "couchdb" in str(resp.headers).lower()
        except (TimeoutError, urllib.error.URLError, OSError):
            return False
