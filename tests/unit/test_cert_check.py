import os
import tempfile
from datetime import UTC, datetime, timedelta

from blocksec.utils.cert_check import (
    check_algorithm,
    days_until_expiry,
    get_cert_info,
    is_expired,
    is_expiring_soon,
    load_certificate,
)


def _generate_self_signed_cert(days_valid: int = 365) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _write_temp_cert(days_valid: int = 365) -> str:
    pem = _generate_self_signed_cert(days_valid)
    fd, path = tempfile.mkstemp(suffix=".pem")
    os.write(fd, pem.encode())
    os.close(fd)
    return path


def test_load_certificate_valid():
    path = _write_temp_cert(365)
    cert = load_certificate(path)
    assert cert is not None
    os.unlink(path)


def test_is_expired():
    path = _write_temp_cert(-1)
    cert = load_certificate(path)
    assert is_expired(cert)
    os.unlink(path)


def test_is_not_expired():
    path = _write_temp_cert(365)
    cert = load_certificate(path)
    assert not is_expired(cert)
    os.unlink(path)


def test_is_expiring_soon():
    path = _write_temp_cert(10)
    cert = load_certificate(path)
    assert is_expiring_soon(cert)
    os.unlink(path)


def test_is_not_expiring_soon():
    path = _write_temp_cert(365)
    cert = load_certificate(path)
    assert not is_expiring_soon(cert)
    os.unlink(path)


def test_days_until_expiry():
    path = _write_temp_cert(100)
    cert = load_certificate(path)
    days = days_until_expiry(cert)
    assert 98 <= days <= 101
    os.unlink(path)


def test_check_algorithm_sha256():
    path = _write_temp_cert(365)
    cert = load_certificate(path)
    algo = check_algorithm(cert)
    assert algo["algorithm"] == "sha256"
    assert len(algo["issues"]) == 0
    os.unlink(path)


def test_get_cert_info():
    path = _write_temp_cert(365)
    cert = load_certificate(path)
    info = get_cert_info(cert)
    assert info["subject_cn"] == "test.example.com"
    assert not info["expired"]
    assert info["days_remaining"] >= 364
    os.unlink(path)


def test_load_certificate_nonexistent():
    cert = load_certificate("/nonexistent/cert.pem")
    assert cert is None


def test_load_certificate_not_a_cert():
    fd, path = tempfile.mkstemp(suffix=".pem")
    os.write(fd, b"not a certificate")
    os.close(fd)
    cert = load_certificate(path)
    assert cert is None
    os.unlink(path)
