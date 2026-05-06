"""测试运行时扫描器的检测模块。"""

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from blocksec.scanners.fabric_runtime.cert_check import CertCheck
from blocksec.scanners.fabric_runtime.couchdb_check import CouchDBCheck


class TestCouchDBCheck:
    def test_port_closed(self):
        chk = CouchDBCheck()
        findings = chk.check_port("127.0.0.1", 59999)
        assert len(findings) == 0

    def test_port_open_not_couchdb(self):
        import socket
        import threading
        import time

        port = 59998

        def server():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            sock.listen(1)
            sock.settimeout(3)
            try:
                conn, _ = sock.accept()
                conn.sendall(b"HTTP/1.1 200 OK\r\n\r\nNot CouchDB\r\n")
                conn.close()
            except TimeoutError:
                pass
            sock.close()

        t = threading.Thread(target=server, daemon=True)
        t.start()
        time.sleep(0.2)

        chk = CouchDBCheck()
        findings = chk.check_port("127.0.0.1", port)
        assert len(findings) == 1
        assert findings[0].rule_id == "FABRIC_RUNTIME_PORT_OPEN"


class TestCertCheck:
    def test_no_certs_in_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            chk = CertCheck()
            findings = chk.scan_directory(tmpdir)
            assert len(findings) == 0

    def test_cert_file_expired(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
            ]
        )

        not_before = datetime(2020, 1, 1, tzinfo=UTC)
        not_after = datetime(2020, 12, 31, tzinfo=UTC)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .sign(key, hashes.SHA256())
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "expired.crt"
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            chk = CertCheck()
            findings = chk.scan_directory(tmpdir)
            assert len(findings) == 1
            assert findings[0].rule_id == "FABRIC_RUNTIME_CERT_EXPIRY"
            assert findings[0].severity == "HIGH"
            assert "已过期" in findings[0].title

    def test_cert_file_valid(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
            ]
        )

        not_before = datetime.now(UTC) - timedelta(days=365)
        not_after = datetime.now(UTC) + timedelta(days=365)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .sign(key, hashes.SHA256())
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "valid.crt"
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            chk = CertCheck()
            findings = chk.scan_directory(tmpdir)
            assert len(findings) == 1
            assert findings[0].severity == "INFO"
            assert "天过期" in findings[0].title


class TestRuntimeScannerIntegration:
    def test_scan_without_docker(self):
        from blocksec.api import scan_fabric_runtime

        result = scan_fabric_runtime(".")
        assert result is not None
        assert result.summary is not None

    def test_runtime_scanner_type_mismatch(self):
        from blocksec.scanners.fabric_runtime.scanner import FabricRuntimeScanner

        scanner = FabricRuntimeScanner()
        assert scanner.can_handle("fabric_runtime") is True
        assert scanner.can_handle("fabric_config") is False
        assert scanner.can_handle("fabric") is False

    def test_runtime_findings_have_correct_category(self):
        from blocksec.api import scan_fabric_runtime
        from blocksec.models.finding import Category

        result = scan_fabric_runtime(".")
        for f in result.findings:
            assert f.category == Category.FABRIC_RUNTIME
