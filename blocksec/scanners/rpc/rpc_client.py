"""JSON-RPC client for Ethereum node security probing."""

import socket
import ssl

import httpx

RPC_METHODS = {
    "web3_clientVersion": {"method": "web3_clientVersion", "params": [], "risk": "info_leak"},
    "net_version": {"method": "net_version", "params": [], "risk": "info_leak"},
    "eth_blockNumber": {"method": "eth_blockNumber", "params": [], "risk": "low"},
    "admin_nodeInfo": {"method": "admin_nodeInfo", "params": [], "risk": "critical"},
    "admin_peers": {"method": "admin_peers", "params": [], "risk": "critical"},
    "personal_listAccounts": {"method": "personal_listAccounts", "params": [], "risk": "critical"},
    "debug_traceTransaction": {"method": "debug_traceTransaction", "params": ["0x0"], "risk": "high"},
    "txpool_content": {"method": "txpool_content", "params": [], "risk": "medium"},
    "eth_accounts": {"method": "eth_accounts", "params": [], "risk": "medium"},
}

TIMEOUT = 8.0


def probe_rpc(target_url: str) -> list[dict]:
    """Send a series of JSON-RPC probes and report findings."""
    findings: list[dict] = []
    if not target_url.startswith("http"):
        target_url = f"http://{target_url}"

    try:
        body = {"jsonrpc": "2.0", "method": "web3_clientVersion", "params": [], "id": 1}
        resp = httpx.post(target_url, json=body, timeout=TIMEOUT)
        if resp.status_code != 200:
            return findings
    except Exception:
        return findings

    data = resp.json()
    client_ver = data.get("result", "")

    if client_ver:
        findings.append({
            "check": "rpc_version_exposed",
            "severity": "LOW",
            "evidence": f"Client version exposed: {client_ver}",
            "description": "RPC endpoint reveals client version, helping attackers target known vulnerabilities.",
        })

    for name, cfg in RPC_METHODS.items():
        if name == "web3_clientVersion":
            continue
        try:
            resp = httpx.post(
                target_url,
                json={"jsonrpc": "2.0", "method": cfg["method"], "params": cfg["params"], "id": 1},
                timeout=TIMEOUT,
            )
            r = resp.json()
            if "error" in r:
                code = r["error"].get("code", 0)
                if code in (-32601, -32000):
                    continue
            if "result" in r and r["result"] is not None and r["result"] != []:
                findings.append({
                    "check": f"rpc_{name}",
                    "severity": "HIGH" if cfg["risk"] == "critical" else "MEDIUM" if cfg["risk"] == "high" else "LOW",
                    "evidence": f"Method accessible: {cfg['method']}",
                    "description": f"Namespace {name.split('_')[0]} accessible. Risk: {cfg['risk']}.",
                })
        except Exception:
            pass

    return findings


def check_cors(target_url: str) -> dict | None:
    """Check if CORS allows arbitrary origins."""
    try:
        resp = httpx.options(
            target_url,
            headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "POST"},
            timeout=TIMEOUT,
        )
        acao = resp.headers.get("access-control-allow-origin", "")
        if acao == "*" or acao == "https://evil.com":
            return {
                "check": "rpc_cors_wildcard",
                "severity": "HIGH",
                "evidence": f"CORS allows arbitrary origin: {acao}",
                "description": "RPC endpoint CORS is misconfigured, allowing malicious websites to make RPC calls.",
            }
    except Exception:
        pass
    return None


def check_tls(host: str, port: int = 8545) -> dict:
    """Check if TLS is available on the RPC endpoint."""
    result = {"tls": False, "cert": None}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        try:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                result["tls"] = True
                cert_bin = tls.getpeercert(binary_form=True)
                if cert_bin:
                    from datetime import UTC, datetime

                    from cryptography import x509

                    c = x509.load_der_x509_certificate(cert_bin)
                    result["cert"] = {
                        "subject": str(c.subject.rfc4514_string()),
                        "expired": datetime.now(UTC) > c.not_valid_after_utc,
                        "not_after": c.not_valid_after_utc.isoformat(),
                    }
        except ssl.SSLError:
            pass
        finally:
            sock.close()
    except Exception:
        pass
    return result
