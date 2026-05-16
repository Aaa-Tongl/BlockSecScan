import os

from blocksec.api.public import scan
from blocksec.models.scan import ScanTarget


def test_scan_fabric_config_vulnerable():
    target_dir = os.path.join(os.path.dirname(__file__), "..", "..", "labs", "fabric-vuln-tls-disabled")
    target = ScanTarget(target_type="fabric_config", path=target_dir)
    result = scan(target)
    assert result.summary.high >= 1
    rule_ids = [f.rule_id for f in result.findings]
    assert "FABRIC_PEER_TLS_DISABLED" in rule_ids


def test_scan_fabric_config_safe():
    target_dir = os.path.join(os.path.dirname(__file__), "..", "..", "labs", "fabric-safe")
    target = ScanTarget(target_type="fabric_config", path=target_dir)
    result = scan(target)
    assert result.summary.critical == 0
    assert result.summary.high == 0


def test_scan_result_has_summary():
    target_dir = os.path.join(os.path.dirname(__file__), "..", "..", "labs", "fabric-vuln-tls-disabled")
    target = ScanTarget(target_type="fabric_config", path=target_dir)
    result = scan(target)
    assert result.summary.total == len(result.findings)
    assert result.scan_id
    assert result.duration_seconds >= 0
