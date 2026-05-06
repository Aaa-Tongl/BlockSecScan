"""证书有效期检测模块。

解析 X.509 证书文件，检测：
- 证书是否已过期
- 证书是否即将过期（30 天内）
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from blocksec.models.finding import Finding, FindingLocation, Severity

CERT_EXPIRY_WARN_DAYS = 30

CERT_FILE_PATTERNS = ["*.crt", "*.pem", "*.cert", "*.cer", "ca-cert.pem", "tlsca-cert.pem"]


class CertCheck:
    def scan_directory(self, target_path: str) -> list[Finding]:
        target = Path(target_path)
        findings: list[Finding] = []

        cert_files: list[Path] = []
        for pattern in CERT_FILE_PATTERNS:
            cert_files.extend(target.rglob(pattern))

        seen = set()
        for cert_path in cert_files:
            abs_path = str(cert_path.resolve())
            if abs_path in seen:
                continue
            seen.add(abs_path)

            try:
                result = self._check_single_cert(cert_path)
                if result:
                    findings.append(result)
            except Exception:
                continue

        return findings

    def _check_single_cert(self, cert_path: Path) -> Finding | None:
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            return None

        try:
            with open(cert_path, "rb") as f:
                cert_data = f.read()
        except OSError:
            return None

        try:
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        except Exception:
            try:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
            except Exception:
                return None

        not_after = cert.not_valid_after_utc
        now = datetime.now(UTC)
        delta = not_after - now

        if delta.total_seconds() <= 0:
            severity = Severity.HIGH
            desc_suffix = "已过期"
            evidence = f"{cert_path.name}: 已过期 (过期时间: {not_after.isoformat()})"
        elif delta.days <= CERT_EXPIRY_WARN_DAYS:
            severity = Severity.MEDIUM
            desc_suffix = f"将在 {delta.days} 天后过期"
            evidence = f"{cert_path.name}: {delta.days} 天后过期 ({not_after.isoformat()})"
        else:
            severity = Severity.INFO
            desc_suffix = f"还有 {delta.days} 天过期"
            evidence = f"{cert_path.name}: {delta.days} 天后过期 ({not_after.isoformat()})"

        subject = cert.subject.rfc4514_string()

        return Finding(
            rule_id="FABRIC_RUNTIME_CERT_EXPIRY",
            severity=severity,
            title=f"证书 {cert_path.name} {desc_suffix}",
            description=(
                f"证书文件 {cert_path} {desc_suffix}。"
                f"Subject: {subject}。过期后节点间 TLS 通信将失败。"
            ),
            location=FindingLocation(file_path=str(cert_path), start_line=0, end_line=0),
            evidence=evidence,
            remediation=(
                "更新证书并重启相关服务。"
                if delta.total_seconds() <= 0
                else f"在 {delta.days} 天内更新证书，避免服务中断。"
            ),
            references=["https://hyperledger-fabric.readthedocs.io/en/latest/enable_tls.html"],
            scanner_name="fabric_runtime",
            confidence=1.0,
        )
