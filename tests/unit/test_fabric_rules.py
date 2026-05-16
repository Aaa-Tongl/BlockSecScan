import os

from blocksec.rule_engine.engine import RuleEngine
from blocksec.rule_engine.parser import RuleParser

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "blocksec", "rules", "fabric")


def _load_rule(rule_id: str):
    rules = RuleParser.load_rules(RULES_DIR)
    for r in rules:
        if r.id == rule_id:
            return r
    raise ValueError(f"Rule not found: {rule_id}")


def test_peer_tls_disabled_detected():
    rule = _load_rule("FABRIC_PEER_TLS_DISABLED")
    finding = RuleEngine.match_file("core.yaml", "CORE_PEER_TLS_ENABLED=false", rule)
    assert finding is not None
    assert finding.severity.value == "HIGH"


def test_peer_tls_enabled_passes():
    rule = _load_rule("FABRIC_PEER_TLS_DISABLED")
    finding = RuleEngine.match_file("core.yaml", "CORE_PEER_TLS_ENABLED=true", rule)
    assert finding is None


def test_orderer_tls_disabled_detected():
    rule = _load_rule("FABRIC_ORDERER_TLS_DISABLED")
    finding = RuleEngine.match_file("orderer.yaml", "ORDERER_GENERAL_TLS_ENABLED=false", rule)
    assert finding is not None


def test_couchdb_exposed_detected():
    rule = _load_rule("FABRIC_COUCHDB_EXPOSED")
    finding = RuleEngine.match_file("docker-compose.yaml", 'ports:\n  - "5984:5984"', rule)
    assert finding is not None
    assert finding.severity.value == "HIGH"


def test_couchdb_not_exposed_passes():
    rule = _load_rule("FABRIC_COUCHDB_EXPOSED")
    finding = RuleEngine.match_file("docker-compose.yaml", "ports:\n  - 7051:7051", rule)
    assert finding is None


def test_couchdb_weak_password_detected():
    rule = _load_rule("FABRIC_COUCHDB_WEAK_PASSWORD")
    finding = RuleEngine.match_file(".env", "COUCHDB_USER=admin", rule)
    assert finding is not None


def test_debug_log_detected():
    rule = _load_rule("FABRIC_DEBUG_LOG_ENABLED")
    finding = RuleEngine.match_file("core.yaml", "FABRIC_LOGGING_SPEC=DEBUG", rule)
    assert finding is not None


def test_debug_log_info_passes():
    rule = _load_rule("FABRIC_DEBUG_LOG_ENABLED")
    finding = RuleEngine.match_file("core.yaml", "FABRIC_LOGGING_SPEC=INFO", rule)
    assert finding is None


def test_container_root_detected():
    rule = _load_rule("FABRIC_CONTAINER_RUNS_AS_ROOT")
    finding = RuleEngine.match_file("docker-compose.yaml", "user: root", rule)
    assert finding is not None


def test_docker_sock_mounted_detected():
    rule = _load_rule("FABRIC_DOCKER_SOCK_MOUNTED")
    finding = RuleEngine.match_file(
        "docker-compose.yaml", "volumes:\n  - /var/run/docker.sock:/var/run/docker.sock", rule
    )
    assert finding is not None


def test_sensitive_host_mount_detected():
    rule = _load_rule("FABRIC_SENSITIVE_HOST_MOUNT")
    finding = RuleEngine.match_file("docker-compose.yaml", "volumes:\n  - /etc/passwd:/mnt/passwd", rule)
    assert finding is not None


def test_plaintext_password_detected():
    rule = _load_rule("FABRIC_PLAINTEXT_PASSWORD")
    finding = RuleEngine.match_file(".env", 'DATABASE_PASSWORD="mysecret123"', rule)
    assert finding is not None


def test_private_key_detected():
    rule = _load_rule("FABRIC_PRIVATE_KEY_IN_REPO")
    content = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B\n-----END PRIVATE KEY-----"
    finding = RuleEngine.match_file("key_sk", content, rule)
    assert finding is not None


def test_weak_endorsement_detected():
    rule = _load_rule("FABRIC_WEAK_ENDORSEMENT_POLICY")
    finding = RuleEngine.match_file(
        "configtx.yaml",
        'Endorsement: OutOf(1, "Org1MSP.member")',
        rule,
    )
    assert finding is not None


def test_tls_client_auth_disabled_detected():
    rule = _load_rule("FABRIC_TLS_CLIENT_AUTH_DISABLED")
    finding = RuleEngine.match_file("core.yaml", "clientAuthRequired: false", rule)
    assert finding is not None
    assert finding.severity.value == "MEDIUM"


def test_tls_client_auth_enabled_passes():
    rule = _load_rule("FABRIC_TLS_CLIENT_AUTH_DISABLED")
    finding = RuleEngine.match_file("core.yaml", "clientAuthRequired: true", rule)
    assert finding is None


def test_cert_expired_handler():
    import os
    import tempfile
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired.example.com")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=365))
        .not_valid_after(now - timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    fd, path = tempfile.mkstemp(suffix=".pem")
    os.write(fd, pem.encode())
    os.close(fd)

    rule = _load_rule("FABRIC_CERT_EXPIRED")
    finding = RuleEngine.match_file(path, "", rule)
    os.unlink(path)

    assert finding is not None
    assert finding.severity.value == "HIGH"
    assert "expired" in finding.title.lower()
