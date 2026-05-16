import json
import os

from blocksec.api.public import scan
from blocksec.models.scan import ScanTarget

LABS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "labs")


def _get_lab_dirs():
    return [
        d
        for d in os.listdir(LABS_DIR)
        if os.path.isdir(os.path.join(LABS_DIR, d))
    ]


def _load_expected(lab_dir: str) -> dict:
    path = os.path.join(LABS_DIR, lab_dir, "expected_findings.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def test_lab_fabric_safe():
    target = ScanTarget(
        target_type="fabric_config", path=os.path.join(LABS_DIR, "fabric-safe")
    )
    result = scan(target)
    assert result.summary.critical == 0
    assert result.summary.high == 0


def test_lab_fabric_vuln_tls_disabled():
    target = ScanTarget(
        target_type="fabric_config",
        path=os.path.join(LABS_DIR, "fabric-vuln-tls-disabled"),
    )
    result = scan(target)
    rule_ids = [f.rule_id for f in result.findings]
    assert "FABRIC_PEER_TLS_DISABLED" in rule_ids
    # Also has FABRIC_DOCKER_SOCK_MOUNTED and FABRIC_DEBUG_LOG_ENABLED
    assert len(result.findings) >= 1
