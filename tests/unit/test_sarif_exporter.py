import json

from blocksec.models.finding import Category, Finding, Severity
from blocksec.models.scan import ScanResult, ScanSummary, ScanTarget
from blocksec.reports.exporters.sarif_exporter import SarifExporter


def _make_result() -> ScanResult:
    target = ScanTarget(target_type="fabric_config", path="/test/path")
    findings = [
        Finding(
            rule_id="FABRIC_PEER_TLS_DISABLED",
            severity=Severity.HIGH,
            category=Category.FABRIC_CONFIG,
            title="Peer TLS not enabled",
            description="TLS is disabled.",
            file_path="core.yaml",
            line_start=10,
            line_end=10,
            evidence="CORE_PEER_TLS_ENABLED=false",
            remediation="Enable TLS.",
            references=["https://example.com"],
            confidence=0.9,
        ),
        Finding(
            rule_id="FABRIC_DEBUG_LOG_ENABLED",
            severity=Severity.MEDIUM,
            category=Category.FABRIC_CONFIG,
            title="DEBUG log level",
            description="Debug logging.",
            file_path="core.yaml",
            line_start=5,
            line_end=5,
            evidence="FABRIC_LOGGING_SPEC=DEBUG",
            remediation="Set to INFO.",
            confidence=0.7,
        ),
    ]
    summary = ScanSummary(high=1, medium=1, total=2)
    return ScanResult(target=target, findings=findings, summary=summary)


def test_sarif_export_valid_json():
    result = _make_result()
    sarif_str = SarifExporter.export(result)
    data = json.loads(sarif_str)
    assert data["version"] == "2.1.0"
    assert data["$schema"].startswith("https://")


def test_sarif_contains_rules():
    result = _make_result()
    sarif_str = SarifExporter.export(result)
    data = json.loads(sarif_str)
    run = data["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "FABRIC_PEER_TLS_DISABLED" in rule_ids
    assert "FABRIC_DEBUG_LOG_ENABLED" in rule_ids


def test_sarif_contains_results():
    result = _make_result()
    sarif_str = SarifExporter.export(result)
    data = json.loads(sarif_str)
    results = data["runs"][0]["results"]
    assert len(results) == 2


def test_sarif_high_severity_maps_to_error():
    result = _make_result()
    sarif_str = SarifExporter.export(result)
    data = json.loads(sarif_str)
    high_result = [r for r in data["runs"][0]["results"] if r["ruleId"] == "FABRIC_PEER_TLS_DISABLED"][0]
    assert high_result["level"] == "error"


def test_sarif_locations():
    result = _make_result()
    sarif_str = SarifExporter.export(result)
    data = json.loads(sarif_str)
    loc = data["runs"][0]["results"][0]["locations"][0]
    assert "physicalLocation" in loc
    assert "artifactLocation" in loc["physicalLocation"]
    assert "uri" in loc["physicalLocation"]["artifactLocation"]
