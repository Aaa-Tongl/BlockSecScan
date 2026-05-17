import os
import re
from fnmatch import fnmatch
from pathlib import Path

from blocksec.models.finding import Category, Finding, Severity
from blocksec.models.rule import Rule
from blocksec.models.scan import ScanTarget
from blocksec.scanners.base import BaseScanner

WEB3_FILE_PATTERNS = ["*.js", "*.ts", "*.jsx", "*.tsx", "*.sol", "*.vy", "*.env", "*.json", "*.html", "*.vue", "*.py"]
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".next", "dist", "build", ".vercel", "coverage"}

_MAX_UINT = r"(ethers\.MaxUint256|type\(uint256\)\.max|2\s*\*\*\s*256\s*-\s*1|115792089237316195423570985008687907853269984665640564039457584007913129639935)"  # noqa: E501

WEB3_CHECKS = [
    {
        "id": "WEB3_PRIVATE_KEY_HARDCODED",
        "severity": "CRITICAL",
        "pattern": r'(private[_\s-]?key|privateKey|PRIVATE_KEY)\s*[:=]\s*["\x27]?(0x[a-fA-F0-9]{64}|[a-fA-F0-9]{64})',
        "title": "Hardcoded Private Key",
        "desc": "A blockchain private key is hardcoded. Anyone with source access can steal all associated funds.",
        "remediation": "Use environment variables or a secrets manager. Never commit private keys to source control.",
    },
    {
        "id": "WEB3_MNEMONIC_HARDCODED",
        "severity": "CRITICAL",
        "pattern": r'(mnemonic|MNEMONIC|seed[_\s-]?phrase|SEED_PHRASE)\s*[:=]\s*["\x27]([a-z]+\s+){11}[a-z]+',
        "title": "Hardcoded Mnemonic / Seed Phrase",
        "desc": "A wallet mnemonic phrase is hardcoded. Exposes all derived private keys.",
        "remediation": "Use environment variables or a secrets manager.",
    },
    {
        "id": "WEB3_INFURA_KEY_LEAK",
        "severity": "HIGH",
        "pattern": r'(INFURA|ALCHEMY|QUICKNODE|MORALIS|RPC[_\s-]?URL).*[=:]\s*["\x27]https?://[^\s"\']+["\x27]',
        "title": "RPC Provider API Key Exposed",
        "desc": "Infura/Alchemy/Moralis API key is hardcoded in frontend code. Exposed in browser devtools.",
        "remediation": "Use a backend proxy for RPC calls. Never embed API keys in client-side code.",
    },
    {
        "id": "WEB3_DANGEROUS_APPROVE",
        "severity": "HIGH",
        "pattern": r"\.approve\s*\(\s*[^,]+,\s*" + _MAX_UINT,
        "title": "Unlimited Token Approval",
        "desc": "Unlimited ERC20 approve detected. A compromised contract can drain all approved tokens.",
        "remediation": "Approve only the exact amount needed, or use permit/allowance patterns.",
    },
    {
        "id": "WEB3_RAW_SIGN_MESSAGE",
        "severity": "MEDIUM",
        "pattern": r'(signMessage|signTypedData|eth_sign|personal_sign)\s*\(',
        "title": "Unprotected eth_sign / signMessage",
        "desc": "Raw signature method detected. Could be used in phishing attacks or signature replay.",
        "remediation": "Always show the user what they're signing. Validate message content before signing.",
    },
    {
        "id": "WEB3_CONTRACT_ADDRESS_HARDCODED",
        "severity": "MEDIUM",
        "pattern": r'CONTRACT[_\s-]?ADDRESS\s*[:=]\s*["\x27]0x[a-fA-F0-9]{40}["\x27]',
        "title": "Hardcoded Contract Address",
        "desc": "Contract address is hardcoded rather than configured. Difficult to update across environments.",
        "remediation": "Move contract addresses to environment variables or a config file.",
    },
    {
        "id": "WEB3_MISSING_CSP",
        "severity": "LOW",
        "pattern": r'<meta\s+http-equiv\s*=\s*["\x27]Content-Security-Policy',
        "title": "Missing Content Security Policy",
        "desc": "No CSP header detected in HTML. Increases risk of XSS attacks stealing wallet interactions.",
        "remediation": "Add a strict Content-Security-Policy header to prevent script injection.",
        "negate": True,
    },
    {
        "id": "WEB3_WINDOW_ETHEREUM_INLINE",
        "severity": "LOW",
        "pattern": r'window\.ethereum\s*[!=]==?\s*undefined',
        "title": "Detect window.ethereum usage",
        "desc": "Application accesses window.ethereum directly. Ensure proper wallet connection handling.",
        "remediation": "Use a wallet connection library like wagmi or web3modal for robust wallet handling.",
    },
]


class Web3Scanner(BaseScanner):
    def can_handle(self, target: ScanTarget) -> bool:
        return target.target_type == "web3"

    def scan(self, target: ScanTarget, rules: list[Rule]) -> list[Finding]:
        files = _discover_files(target.path)
        if not files:
            return []

        findings: list[Finding] = []
        for file_path in files:
            content = _read_file(file_path)
            if content is None:
                continue
            for check in WEB3_CHECKS:
                f = _match_check(file_path, content, check)
                if f:
                    findings.append(f)
        return findings


def _discover_files(base_path: str) -> list[str]:
    root = Path(base_path).resolve()
    if not root.exists():
        return []
    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            if any(fnmatch(fname, p) for p in WEB3_FILE_PATTERNS):
                files.append(full)
    return files


def _read_file(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, PermissionError):
        return None


def _match_check(file_path: str, content: str, check: dict) -> Finding | None:
    try:
        m = re.search(check["pattern"], content, re.MULTILINE | re.DOTALL)
    except re.error:
        return None

    if check.get("negate"):
        if m:
            return None
    else:
        if not m:
            return None

    line = content[:m.start()].count("\n") + 1 if m else 1

    evidence = m.group(0)[:120] if m else "not found"

    return Finding(
        rule_id=check["id"],
        severity=Severity[check["severity"]],
        category=Category.WEB3,
        title=check["title"],
        description=check["desc"],
        file_path=file_path,
        line_start=line,
        evidence=evidence,
        remediation=check["remediation"],
        confidence=0.85,
    )
