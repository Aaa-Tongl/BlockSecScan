from blocksec.models.rule import MatchConfig, Rule
from blocksec.rule_engine.engine import RuleEngine


def _make_rule(match_type: str, pattern: str) -> Rule:
    return Rule(
        id="TEST",
        name="Test Rule",
        category="fabric_config",
        severity="HIGH",
        match=MatchConfig(type=match_type, pattern=pattern),
    )


class TestRegexMatch:
    def test_regex_match_found(self):
        rule = _make_rule("regex", r"CORE_PEER_TLS_ENABLED\s*=\s*false")
        finding = RuleEngine.match_file("core.yaml", "CORE_PEER_TLS_ENABLED=false", rule)
        assert finding is not None
        assert finding.rule_id == "TEST"
        assert finding.line_start == 1

    def test_regex_match_not_found(self):
        rule = _make_rule("regex", r"CORE_PEER_TLS_ENABLED\s*=\s*false")
        finding = RuleEngine.match_file("core.yaml", "CORE_PEER_TLS_ENABLED=true", rule)
        assert finding is None

    def test_regex_case_insensitive(self):
        rule = _make_rule("regex", "debug")
        rule.match.case_sensitive = False
        finding = RuleEngine.match_file("test.yaml", "FABRIC_LOGGING_SPEC=DEBUG", rule)
        assert finding is not None

    def test_regex_invalid_pattern(self):
        rule = _make_rule("regex", "[invalid(regex")
        finding = RuleEngine.match_file("test.yaml", "anything", rule)
        assert finding is None


class TestContainsMatch:
    def test_contains_found(self):
        rule = _make_rule("contains", "BEGIN CERTIFICATE")
        finding = RuleEngine.match_file("cert.pem", "-----BEGIN CERTIFICATE-----", rule)
        assert finding is not None

    def test_contains_not_found(self):
        rule = _make_rule("contains", "BEGIN CERTIFICATE")
        finding = RuleEngine.match_file("cert.pem", "-----BEGIN RSA PRIVATE KEY-----", rule)
        assert finding is None


class TestFileNameMatch:
    def test_file_name_match(self):
        rule = _make_rule("file_name", r".*_sk$")
        finding = RuleEngine.match_file("/path/to/abc_sk", "", rule)
        assert finding is not None

    def test_file_name_no_match(self):
        rule = _make_rule("file_name", r".*_sk$")
        finding = RuleEngine.match_file("/path/to/config.yaml", "", rule)
        assert finding is None


class TestYamlPathMatch:
    def test_yaml_path_found(self):
        rule = _make_rule("yaml_path", "peer.tls.enabled")
        rule.match.patterns = ["false"]
        content = "peer:\n  tls:\n    enabled: false\n"
        finding = RuleEngine.match_file("core.yaml", content, rule)
        assert finding is not None


class TestDisabledRule:
    def test_disabled_rule_returns_none(self):
        rule = _make_rule("regex", "test")
        rule.enabled = False
        finding = RuleEngine.match_file("test.yaml", "test", rule)
        assert finding is None


class TestFindingMetadata:
    def test_finding_has_required_fields(self):
        rule = _make_rule("regex", "secret")
        rule.description = "Risk found"
        rule.remediation = "Fix it"
        rule.references = ["https://example.com"]
        finding = RuleEngine.match_file("test.yaml", "my secret key", rule)
        assert finding.description == "Risk found"
        assert finding.remediation == "Fix it"
        assert "https://example.com" in finding.references
        assert finding.confidence > 0.5
