from blocksec.models.finding import Category, Finding, Severity
from blocksec.models.rule import Rule
from blocksec.models.scan import ScanTarget
from blocksec.scanners.base import BaseScanner
from blocksec.scanners.fabric_runtime.docker_check import (
    check_container_env,
    check_container_root,
    check_ports_exposed,
    check_sensitive_mounts,
    get_docker_client,
    get_fabric_containers,
)
from blocksec.scanners.fabric_runtime.tls_check import (
    FABRIC_DEFAULT_PORTS,
    check_couchdb_accessibility,
    check_tls_handshake,
)


class FabricRuntimeScanner(BaseScanner):
    def can_handle(self, target: ScanTarget) -> bool:
        return target.target_type == "fabric_runtime"

    def scan(self, target: ScanTarget, rules: list[Rule]) -> list[Finding]:
        findings: list[Finding] = []

        if target.options.get("local", True):
            findings.extend(self._scan_local_docker(rules))

        if target.options.get("host"):
            host = target.options["host"]
            findings.extend(self._scan_remote_ports(host, rules))

        return findings

    def _scan_local_docker(self, rules: list[Rule]) -> list[Finding]:
        findings: list[Finding] = []
        client = get_docker_client()
        if client is None:
            return findings

        active_rule_ids = {r.id for r in rules if r.enabled}
        rules_by_id = {r.id: r for r in rules}

        try:
            containers = get_fabric_containers(client)
        except Exception:
            return findings

        for container in containers:
            tags = container.image.tags or [container.image.short_id]
            pf = f"container={container.name} image={', '.join(tags)}"

            if "FABRIC_CONTAINER_RUNS_AS_ROOT" in active_rule_ids and check_container_root(container):
                findings.append(self._mk("FABRIC_CONTAINER_RUNS_AS_ROOT", "HIGH", pf, rules_by_id))

            if "FABRIC_COUCHDB_EXPOSED" in active_rule_ids:
                for port in check_ports_exposed(container):
                    if "5984" in port["container_port"]:
                        ev = f"{pf} host={port['host_ip']}:{port['host_port']}"
                        findings.append(self._mk("FABRIC_COUCHDB_EXPOSED", "HIGH", ev, rules_by_id))

            if "FABRIC_DOCKER_SOCK_MOUNTED" in active_rule_ids:
                for mount in check_sensitive_mounts(container):
                    if "docker.sock" in mount.get("source", ""):
                        ev = f"{pf} mount={mount['source']}:{mount['destination']}"
                        findings.append(self._mk("FABRIC_DOCKER_SOCK_MOUNTED", "HIGH", ev, rules_by_id))

            if "FABRIC_SENSITIVE_HOST_MOUNT" in active_rule_ids:
                for mount in check_sensitive_mounts(container):
                    if "docker.sock" not in mount.get("source", ""):
                        ev = f"{pf} mount={mount['source']}:{mount['destination']}"
                        findings.append(self._mk("FABRIC_SENSITIVE_HOST_MOUNT", "HIGH", ev, rules_by_id))

            for env_issue in check_container_env(container):
                ev = f"{pf} {env_issue['var']}"
                if "DEBUG" in env_issue["issue"] and "FABRIC_DEBUG_LOG_ENABLED" in active_rule_ids:
                    findings.append(self._mk("FABRIC_DEBUG_LOG_ENABLED", "MEDIUM", ev, rules_by_id))
                elif "TLS" in env_issue["issue"] and "FABRIC_PEER_TLS_DISABLED" in active_rule_ids:
                    findings.append(self._mk("FABRIC_PEER_TLS_DISABLED", "HIGH", ev, rules_by_id))
                elif "Orderer TLS" in env_issue["issue"] and "FABRIC_ORDERER_TLS_DISABLED" in active_rule_ids:
                    findings.append(self._mk("FABRIC_ORDERER_TLS_DISABLED", "HIGH", ev, rules_by_id))

        return findings

    def _scan_remote_ports(self, host: str, rules: list[Rule]) -> list[Finding]:
        findings: list[Finding] = []
        active_rule_ids = {r.id for r in rules if r.enabled}
        rules_by_id = {r.id: r for r in rules}

        for service, port in FABRIC_DEFAULT_PORTS.items():
            tls_result = check_tls_handshake(host, port)

            if tls_result["reachable"] and not tls_result["tls_enabled"]:
                rule_id = "FABRIC_PEER_TLS_DISABLED" if service == "peer" else None
                if service == "orderer":
                    rule_id = "FABRIC_ORDERER_TLS_DISABLED"
                if rule_id and rule_id in active_rule_ids:
                    ev = f"host={host}:{port} service={service} TLS not detected"
                    findings.append(self._mk(rule_id, "HIGH", ev, rules_by_id))

            if tls_result.get("certificate"):
                cert = tls_result["certificate"]
                if cert.get("expired") and "FABRIC_CERT_EXPIRED" in active_rule_ids:
                    ev = f"host={host}:{port} subject={cert['subject']} expires={cert['not_after']}"
                    findings.append(self._mk("FABRIC_CERT_EXPIRED", "HIGH", ev, rules_by_id))

        if "FABRIC_COUCHDB_EXPOSED" in active_rule_ids:
            couchdb = check_couchdb_accessibility(host)
            if couchdb.get("couchdb_detected"):
                ev = f"host={host}:5984 CouchDB reachable on network"
                findings.append(self._mk("FABRIC_COUCHDB_EXPOSED", "HIGH", ev, rules_by_id))

        return findings

    @staticmethod
    def _mk(rule_id: str, default_severity: str, evidence: str, rules_by_id: dict[str, Rule]) -> Finding:
        matched_rule = rules_by_id.get(rule_id)

        if matched_rule is None:
            return Finding(
                rule_id=rule_id,
                severity=Severity[default_severity],
                category=Category.FABRIC_RUNTIME,
                title=rule_id,
                description="",
                file_path="docker://",
                evidence=evidence,
                remediation="",
                confidence=0.7,
            )

        sev = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }
        conf = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}

        return Finding(
            rule_id=matched_rule.id,
            severity=sev.get(matched_rule.severity.upper(), Severity[default_severity]),
            category=Category.FABRIC_RUNTIME,
            title=matched_rule.name,
            description=matched_rule.description,
            file_path="docker://",
            evidence=evidence,
            remediation=matched_rule.remediation,
            references=matched_rule.references,
            confidence=conf.get(matched_rule.confidence.upper(), 0.7),
            false_positive_note=matched_rule.false_positive_note,
        )
