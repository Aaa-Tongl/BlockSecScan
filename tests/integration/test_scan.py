import json
from pathlib import Path

from blocksec.api import scan_fabric


class TestIntegrationScan:
    def test_scan_safe_lab(self):
        safe_path = Path(__file__).parent.parent.parent / "labs" / "fabric-safe"
        result = scan_fabric(str(safe_path))
        assert result.summary.total == 0, (
            f"Safe lab should have 0 findings, got {result.summary.total}"
        )
        assert len(result.errors) == 0

    def test_scan_vuln_lab(self):
        vuln_path = Path(__file__).parent.parent.parent / "labs" / "fabric-vuln-couchdb-exposed"
        result = scan_fabric(str(vuln_path))

        assert result.summary.high >= 3, f"Expected at least 3 HIGH, got {result.summary.high}"
        assert result.summary.medium >= 1, (
            f"Expected at least 1 MEDIUM, got {result.summary.medium}"
        )

        rule_ids = {f.rule_id for f in result.findings}
        expected_ids = {
            "FABRIC_PEER_TLS_DISABLED",
            "FABRIC_ORDERER_TLS_DISABLED",
            "FABRIC_COUCHDB_EXPOSED",
            "FABRIC_PLAINTEXT_PASSWORD",
            "FABRIC_DEBUG_LOG_ENABLED",
        }
        assert expected_ids.issubset(rule_ids), f"Missing rule IDs: {expected_ids - rule_ids}"

    def test_scan_vuln_against_expected(self):
        vuln_path = Path(__file__).parent.parent.parent / "labs" / "fabric-vuln-couchdb-exposed"
        result = scan_fabric(str(vuln_path))

        with open(Path(vuln_path) / "expected_findings.json") as f:
            expected = json.load(f)

        assert result.summary.critical == expected["expected_critical"]
        assert result.summary.high == expected["expected_high"]
        assert result.summary.medium == expected["expected_medium"]
        assert result.summary.low == expected["expected_low"]

        actual_ids = {f.rule_id for f in result.findings}
        for rule_id in expected["rule_ids"]:
            assert rule_id in actual_ids, f"Expected finding for {rule_id}"

    def test_scan_nonexistent_path(self):
        result = scan_fabric("/nonexistent/path/to/scan")
        assert result.summary.total == 0
        assert len(result.errors) == 0

    def test_json_export(self):
        from blocksec.reports.exporters.json_exporter import JsonExporter

        safe_path = Path(__file__).parent.parent.parent / "labs" / "fabric-vuln-couchdb-exposed"
        result = scan_fabric(str(safe_path))

        exporter = JsonExporter()
        output_path = Path("test_output.json")
        exported = exporter.export(result, output_path)

        assert exported.exists()
        with open(exported, encoding="utf-8") as f:
            data = json.load(f)

        assert data["summary"]["total"] == result.summary.total
        assert len(data["findings"]) == len(result.findings)

        output_path.unlink()
