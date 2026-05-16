from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

WEAK_HASHES = {
    hashes.MD5,
    hashes.SHA1,
}
WEAK_RSA_KEY_SIZE = 2048
WARN_DAYS = 30


def load_certificate(file_path: str) -> x509.Certificate | None:
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except (OSError, PermissionError):
        return None

    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        pass

    try:
        return x509.load_der_x509_certificate(data)
    except Exception:
        pass

    return None


def is_expired(cert: x509.Certificate) -> bool:
    return datetime.now(UTC) > cert.not_valid_after_utc


def days_until_expiry(cert: x509.Certificate) -> int:
    delta = cert.not_valid_after_utc - datetime.now(UTC)
    return max(0, delta.days)


def is_expiring_soon(cert: x509.Certificate, warn_days: int = WARN_DAYS) -> bool:
    return days_until_expiry(cert) <= warn_days


def check_algorithm(cert: x509.Certificate) -> dict:
    issues: list[str] = []

    sig_alg = cert.signature_hash_algorithm
    if sig_alg in WEAK_HASHES:
        issues.append(f"Weak signature algorithm: {sig_alg.name}")

    pubkey = cert.public_key()
    if isinstance(pubkey, rsa.RSAPublicKey):
        key_size = pubkey.key_size
        if key_size < WEAK_RSA_KEY_SIZE:
            issues.append(f"Weak RSA key size: {key_size} bits (minimum {WEAK_RSA_KEY_SIZE})")
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        curve_size = pubkey.curve.key_size
        if curve_size < 256:
            issues.append(f"Weak EC curve size: {curve_size} bits")

    return {"algorithm": sig_alg.name, "issues": issues}


def get_cert_info(cert: x509.Certificate) -> dict:
    try:
        subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = subject[0].value if subject else "unknown"
    except Exception:
        cn = "unknown"

    try:
        issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuer_cn = issuer[0].value if issuer else "unknown"
    except Exception:
        issuer_cn = "unknown"

    return {
        "subject_cn": str(cn),
        "issuer_cn": str(issuer_cn),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "expired": is_expired(cert),
        "days_remaining": days_until_expiry(cert),
        "expiring_soon": is_expiring_soon(cert),
        "algorithm": check_algorithm(cert),
    }
