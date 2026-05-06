from pathlib import Path

from blocksec.core.rule_parser import RuleParser


class TestRuleParser:
    def test_load_all_rules(self):
        rp = RuleParser()
        rules_dir = Path(__file__).parent.parent.parent / "blocksec" / "rules" / "fabric"
        rules = rp.load_rules(str(rules_dir))

        rule_ids = {r.id for r in rules}
        expected = {
            "FABRIC_PEER_TLS_DISABLED",
            "FABRIC_ORDERER_TLS_DISABLED",
            "FABRIC_COUCHDB_EXPOSED",
            "FABRIC_PLAINTEXT_PASSWORD",
            "FABRIC_DEBUG_LOG_ENABLED",
        }
        assert rule_ids == expected, f"Expected {expected}, got {rule_ids}"
        assert all(r.enabled for r in rules)

    def test_rule_severity_values(self):
        rp = RuleParser()
        rules_dir = Path(__file__).parent.parent.parent / "blocksec" / "rules" / "fabric"
        rules = rp.load_rules(str(rules_dir))

        severity_map = {r.id: r.severity for r in rules}
        assert severity_map["FABRIC_PEER_TLS_DISABLED"].value == "HIGH"
        assert severity_map["FABRIC_ORDERER_TLS_DISABLED"].value == "HIGH"
        assert severity_map["FABRIC_COUCHDB_EXPOSED"].value == "HIGH"
        assert severity_map["FABRIC_PLAINTEXT_PASSWORD"].value == "MEDIUM"
        assert severity_map["FABRIC_DEBUG_LOG_ENABLED"].value == "LOW"

    def test_rules_have_required_fields(self):
        rp = RuleParser()
        rules_dir = Path(__file__).parent.parent.parent / "blocksec" / "rules" / "fabric"
        rules = rp.load_rules(str(rules_dir))

        for rule in rules:
            assert rule.id, "Rule missing id"
            assert rule.name, f"Rule {rule.id} missing name"
            assert rule.description, f"Rule {rule.id} missing description"
            assert rule.remediation, f"Rule {rule.id} missing remediation"
            assert rule.match.type, f"Rule {rule.id} missing match type"

    def test_parse_nonexistent_dir(self):
        rp = RuleParser()
        rules = rp.load_rules("/nonexistent/path/to/rules")
        assert rules == []
