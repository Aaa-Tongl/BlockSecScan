"""测试多文档 YAML 规则加载。"""

from pathlib import Path

from blocksec.core.rule_parser import RuleParser


class TestMultiDocYamlRules:
    def test_12_rules_loaded(self):
        rp = RuleParser()
        rules_dir = Path(__file__).parent.parent.parent / "blocksec" / "rules" / "fabric"
        rules = rp.load_rules(str(rules_dir))
        assert len(rules) == 12, f"Expected 12 rules, got {len(rules)}"

    def test_runtime_rules_exist(self):
        rp = RuleParser()
        rules_dir = Path(__file__).parent.parent.parent / "blocksec" / "rules" / "fabric"
        rules = rp.load_rules(str(rules_dir))
        rule_ids = {r.id for r in rules}

        runtime_rules = {
            "FABRIC_RUNTIME_CONTAINER_ROOT",
            "FABRIC_RUNTIME_PRIVILEGED",
            "FABRIC_RUNTIME_SENSITIVE_MOUNT",
            "FABRIC_RUNTIME_HOST_NETWORK",
            "FABRIC_RUNTIME_COUCHDB_ACCESSIBLE",
            "FABRIC_RUNTIME_PORT_OPEN",
            "FABRIC_RUNTIME_CERT_EXPIRY",
        }
        assert runtime_rules.issubset(rule_ids), f"Missing: {runtime_rules - rule_ids}"

    def test_runtime_rules_severity(self):
        rp = RuleParser()
        rules_dir = Path(__file__).parent.parent.parent / "blocksec" / "rules" / "fabric"
        rules = rp.load_rules(str(rules_dir))
        severity_map = {r.id: r.severity.value for r in rules}

        assert severity_map["FABRIC_RUNTIME_PRIVILEGED"] == "CRITICAL"
        assert severity_map["FABRIC_RUNTIME_CERT_EXPIRY"] == "HIGH"
        assert severity_map["FABRIC_RUNTIME_HOST_NETWORK"] == "MEDIUM"

    def test_runtime_rules_all_enabled(self):
        rp = RuleParser()
        rules_dir = Path(__file__).parent.parent.parent / "blocksec" / "rules" / "fabric"
        rules = rp.load_rules(str(rules_dir))
        runtime_rules = [r for r in rules if r.id.startswith("FABRIC_RUNTIME_")]
        assert all(r.enabled for r in runtime_rules)
