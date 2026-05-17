from blocksec.models.finding import Category, Finding, Severity
from blocksec.models.rule import Rule
from blocksec.models.scan import ScanTarget
from blocksec.scanners.base import BaseScanner
from blocksec.scanners.rpc.rpc_client import check_cors, check_tls, probe_rpc


class RpcScanner(BaseScanner):
    def can_handle(self, target: ScanTarget) -> bool:
        return target.target_type == "rpc"

    def scan(self, target: ScanTarget, rules: list[Rule]) -> list[Finding]:
        url = target.path
        findings: list[Finding] = []

        if "://" not in url:
            url = f"http://{url}"

        rpc_findings = probe_rpc(url)
        for f in rpc_findings:
            findings.append(
                Finding(
                    rule_id=f["check"].upper(),
                    severity=Severity[f["severity"]],
                    category=Category.RPC,
                    title=f["check"].replace("_", " ").title(),
                    description=f["description"],
                    file_path=url,
                    evidence=f["evidence"],
                    remediation=_remediation(f["check"]),
                    confidence=0.9,
                )
            )

        cors_finding = check_cors(url)
        if cors_finding:
            findings.append(
                Finding(
                    rule_id=cors_finding["check"].upper(),
                    severity=Severity[cors_finding["severity"]],
                    category=Category.RPC,
                    title="CORS Misconfiguration",
                    description=cors_finding["description"],
                    file_path=url,
                    evidence=cors_finding["evidence"],
                    remediation="Set Access-Control-Allow-Origin to trusted domains only.",
                    confidence=0.9,
                )
            )

        host = target.options.get("host", "")
        if host:
            tls = check_tls(host)
            if not tls["tls"]:
                findings.append(
                    Finding(
                        rule_id="RPC_TLS_DISABLED",
                        severity=Severity.HIGH,
                        category=Category.RPC,
                        title="RPC TLS not enabled",
                        description="RPC uses plain HTTP, no TLS. Keys transmitted in cleartext.",
                        file_path=f"{host}:8545",
                        evidence="No TLS handshake possible on RPC port",
                        remediation="Enable TLS on the RPC endpoint. Use nginx or Caddy as TLS reverse proxy.",
                        confidence=0.9,
                    )
                )
            elif tls.get("cert", {}).get("expired"):
                findings.append(
                    Finding(
                        rule_id="RPC_CERT_EXPIRED",
                        severity=Severity.HIGH,
                        category=Category.RPC,
                        title="RPC TLS certificate expired",
                        description=f"Certificate expired: {tls['cert']['not_after']}",
                        file_path=f"{host}:8545",
                        evidence=f"Subject: {tls['cert']['subject']}",
                        remediation="Renew the TLS certificate immediately.",
                        confidence=0.9,
                    )
                )

        return findings


def _remediation(check: str) -> str:
    fixes = {
        "rpc_version_exposed": "Disable web3_clientVersion or configure a reverse proxy to strip version info.",
        "rpc_admin_nodeInfo": "Disable admin namespace entirely. Never expose admin RPC to any network.",
        "rpc_admin_peers": "Disable admin namespace entirely.",
        "rpc_personal_listAccounts": "Disable personal namespace. Use Clef or external signer instead.",
        "rpc_debug_traceTransaction": "Disable debug namespace on public endpoints.",
        "rpc_txpool_content": "Restrict txpool access to trusted IPs only.",
        "rpc_eth_accounts": "Disable eth_accounts. Do not store keys on the node.",
    }
    return fixes.get(check, "Restrict RPC access with firewall rules, authentication, and disable unnecessary APIs.")
