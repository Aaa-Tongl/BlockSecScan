import os

from blocksec.rule_engine.parser import RuleParser


def test_load_rules_from_dir():
    rules_dir = os.path.join(os.path.dirname(__file__), "..", "..", "blocksec", "rules", "fabric")
    rules = RuleParser.load_rules(rules_dir)
    assert len(rules) >= 12


def test_load_rules_with_category_filter():
    rules_dir = os.path.join(os.path.dirname(__file__), "..", "..", "blocksec", "rules", "fabric")
    rules = RuleParser.load_rules(rules_dir, category="fabric_config")
    assert all(r.category == "fabric_config" for r in rules)


def test_load_rules_nonexistent_dir():
    rules = RuleParser.load_rules("/nonexistent/path")
    assert rules == []


def test_parse_single_rule():
    data = {
        "id": "TEST_RULE",
        "name": "Test",
        "category": "fabric_config",
        "severity": "HIGH",
        "match": {"type": "regex", "pattern": "test"},
    }
    rules = RuleParser._parse_rule(data)
    assert rules is not None
    assert rules.id == "TEST_RULE"
    assert rules.severity == "HIGH"


def test_parse_rule_missing_id():
    assert RuleParser._parse_rule({"name": "test", "match": {"type": "regex"}}) is None


def test_parse_rule_missing_match():
    assert RuleParser._parse_rule({"id": "TEST", "name": "test"}) is None
