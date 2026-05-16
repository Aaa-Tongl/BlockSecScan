import json
import os

from blocksec.api.public import scan
from blocksec.models.scan import ScanTarget

LABS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "labs")


def _scan_lab(name: str):
    target = ScanTarget(target_type="fabric_config", path=os.path.join(LABS_DIR, name))
    return scan(target)


def _load_expected(lab_dir: str) -> dict:
    path = os.path.join(LABS_DIR, lab_dir, "expected_findings.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


class TestLabFabricSafe:
    def test_no_high_or_critical(self):
        result = _scan_lab("fabric-safe")
        assert result.summary.critical == 0
        assert result.summary.high == 0


class TestLabFabricVulnTlsDisabled:
    def test_detects_tls_disabled(self):
        result = _scan_lab("fabric-vuln-tls-disabled")
        rule_ids = [f.rule_id for f in result.findings]
        assert "FABRIC_PEER_TLS_DISABLED" in rule_ids
        assert len(result.findings) >= 1


class TestLabFabricVulnPrivateKeyLeak:
    def test_detects_private_key(self):
        result = _scan_lab("fabric-vuln-private-key-leak")
        rule_ids = [f.rule_id for f in result.findings]
        assert "FABRIC_PRIVATE_KEY_IN_REPO" in rule_ids
        assert result.summary.high >= 1


class TestLabFabricVulnCouchdbExposed:
    def test_detects_couchdb_exposure(self):
        result = _scan_lab("fabric-vuln-couchdb-exposed")
        rule_ids = [f.rule_id for f in result.findings]
        assert "FABRIC_COUCHDB_EXPOSED" in rule_ids
        assert "FABRIC_COUCHDB_WEAK_PASSWORD" in rule_ids
        assert result.summary.high >= 2


class TestLabFabricVulnDebugLog:
    def test_detects_debug_log(self):
        result = _scan_lab("fabric-vuln-debug-log")
        rule_ids = [f.rule_id for f in result.findings]
        assert "FABRIC_DEBUG_LOG_ENABLED" in rule_ids
        assert result.summary.medium >= 1


class TestLabFabricVulnRootContainer:
    def test_detects_root_container(self):
        result = _scan_lab("fabric-vuln-root-container")
        rule_ids = [f.rule_id for f in result.findings]
        assert "FABRIC_CONTAINER_RUNS_AS_ROOT" in rule_ids
        assert result.summary.medium >= 1


class TestLabFabricVulnPlaintextPassword:
    def test_detects_plaintext_password(self):
        result = _scan_lab("fabric-vuln-plaintext-password")
        rule_ids = [f.rule_id for f in result.findings]
        assert "FABRIC_PLAINTEXT_PASSWORD" in rule_ids
        assert result.summary.medium >= 1
