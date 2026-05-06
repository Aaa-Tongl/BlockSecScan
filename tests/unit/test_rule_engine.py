from blocksec.core.rule_engine import RuleEngine
from blocksec.models.finding import Severity
from blocksec.models.rule import MatchCondition, MatchType, Rule, TargetSpec


def _make_rule(**kwargs) -> Rule:
    target_files = kwargs.pop("target_files", ["*"])
    defaults = {
        "id": "TEST_RULE",
        "name": "Test Rule",
        "category": "Test",
        "severity": Severity.HIGH,
        "target": TargetSpec(files=target_files),
        "match": MatchCondition(),
        "description": "Test",
        "remediation": "Fix",
    }
    defaults.update(kwargs)
    return Rule(**defaults)


class TestRuleEnginePattern:
    def test_simple_pattern_match(self):
        engine = RuleEngine()
        rule = _make_rule(
            id="TEST", name="Test", match=MatchCondition(type=MatchType.PATTERN, pattern="password")
        )
        results = engine.match_file(rule, "test.txt", "admin\npassword=123\nhello")
        assert len(results) == 1
        assert results[0][0] == 2
        assert "password=123" in results[0][2]

    def test_pattern_case_insensitive(self):
        engine = RuleEngine()
        rule = _make_rule(
            match=MatchCondition(type=MatchType.PATTERN, pattern="DEBUG", case_sensitive=False)
        )
        results = engine.match_file(rule, "test.txt", "LogLevel=debug\ninfo")
        assert len(results) == 1

    def test_pattern_case_sensitive(self):
        engine = RuleEngine()
        rule = _make_rule(
            match=MatchCondition(type=MatchType.PATTERN, pattern="DEBUG", case_sensitive=True)
        )
        results = engine.match_file(rule, "test.txt", "LogLevel=debug")
        assert len(results) == 0

    def test_pattern_negate(self):
        engine = RuleEngine()
        rule = _make_rule(
            match=MatchCondition(type=MatchType.PATTERN, pattern="error", negate=True)
        )
        content = "line1 ok\nline2 ok\nline3 error\nline4 ok"
        results = engine.match_file(rule, "test.txt", content)
        assert len(results) == 3

    def test_pattern_not_found(self):
        engine = RuleEngine()
        rule = _make_rule(match=MatchCondition(type=MatchType.PATTERN, pattern="nonexistent"))
        results = engine.match_file(rule, "test.txt", "hello\nworld")
        assert len(results) == 0

    def test_disabled_rule(self):
        engine = RuleEngine()
        rule = _make_rule(
            match=MatchCondition(type=MatchType.PATTERN, pattern="test"), enabled=False
        )
        results = engine.match_file(rule, "test.txt", "test data")
        assert len(results) == 0

    def test_file_pattern_mismatch(self):
        engine = RuleEngine()
        rule = _make_rule(
            match=MatchCondition(
                type=MatchType.PATTERN, pattern="test", file_pattern="docker-compose*"
            )
        )
        results = engine.match_file(rule, "core.yaml", "test data")
        assert len(results) == 0

    def test_file_pattern_match(self):
        engine = RuleEngine()
        rule = _make_rule(
            match=MatchCondition(
                type=MatchType.PATTERN, pattern="test", file_pattern="docker-compose*"
            )
        )
        results = engine.match_file(rule, "docker-compose.yaml", "test data")
        assert len(results) == 1


class TestRuleEngineKeyValue:
    def test_simple_key_value_match(self):
        engine = RuleEngine()
        rule = _make_rule(
            match=MatchCondition(
                type=MatchType.KEY_VALUE, key="CORE_PEER_TLS_ENABLED", value="false"
            )
        )
        results = engine.match_file(rule, ".env", "CORE_PEER_TLS_ENABLED=false")
        assert len(results) == 1

    def test_key_value_no_match(self):
        engine = RuleEngine()
        rule = _make_rule(
            match=MatchCondition(
                type=MatchType.KEY_VALUE, key="CORE_PEER_TLS_ENABLED", value="false"
            )
        )
        results = engine.match_file(rule, ".env", "CORE_PEER_TLS_ENABLED=true")
        assert len(results) == 0

    def test_key_value_case_insensitive(self):
        engine = RuleEngine()
        rule = _make_rule(
            match=MatchCondition(
                type=MatchType.KEY_VALUE,
                key="fabric_logging_spec",
                value="debug",
                case_sensitive=False,
            )
        )
        results = engine.match_file(rule, ".env", "FABRIC_LOGGING_SPEC=DEBUG")
        assert len(results) == 1

    def test_key_value_docker_compose_env(self):
        engine = RuleEngine()
        rule = _make_rule(
            match=MatchCondition(
                type=MatchType.KEY_VALUE, key="CORE_PEER_TLS_ENABLED", value="false"
            )
        )
        results = engine.match_file(
            rule, "docker-compose.yaml", "      - CORE_PEER_TLS_ENABLED=false"
        )
        assert len(results) == 1

    def test_key_value_docker_compose_env_with_quotes(self):
        engine = RuleEngine()
        rule = _make_rule(
            match=MatchCondition(type=MatchType.KEY_VALUE, key="CORE_PEER_ID", value="peer0.org1")
        )
        results = engine.match_file(
            rule, "docker-compose.yaml", '      - CORE_PEER_ID="peer0.org1"'
        )
        assert len(results) == 1


class TestRuleEngineRegex:
    def test_regex_match(self):
        engine = RuleEngine()
        rule = _make_rule(match=MatchCondition(type=MatchType.REGEX, regex=r'"\d+:5984"'))
        results = engine.match_file(rule, "docker-compose.yaml", '      - "5984:5984"')
        assert len(results) == 1

    def test_regex_no_match_localhost(self):
        engine = RuleEngine()
        rule = _make_rule(match=MatchCondition(type=MatchType.REGEX, regex=r'"\d+:5984"'))
        results = engine.match_file(rule, "docker-compose.yaml", '      - "127.0.0.1:5984:5984"')
        assert len(results) == 0

    def test_regex_case_insensitive(self):
        engine = RuleEngine()
        rule = _make_rule(
            match=MatchCondition(type=MatchType.REGEX, regex=r"password\s*=", case_sensitive=False)
        )
        results = engine.match_file(rule, ".env", "PASSWORD=admin123")
        assert len(results) == 1

    def test_regex_invalid_pattern(self):
        engine = RuleEngine()
        rule = _make_rule(match=MatchCondition(type=MatchType.REGEX, regex=r"[invalid"))
        results = engine.match_file(rule, "test.txt", "anything")
        assert len(results) == 0


class TestFindingSummary:
    def test_summary_counts(self):
        from blocksec.models.finding import Finding, FindingLocation
        from blocksec.models.scan import FindingSummary

        findings = [
            Finding(
                rule_id="R1",
                severity=Severity.HIGH,
                title="H1",
                description="D",
                location=FindingLocation(file_path="a", start_line=1, end_line=1),
                evidence="e",
                remediation="r",
            ),
            Finding(
                rule_id="R2",
                severity=Severity.HIGH,
                title="H2",
                description="D",
                location=FindingLocation(file_path="a", start_line=2, end_line=2),
                evidence="e",
                remediation="r",
            ),
            Finding(
                rule_id="R3",
                severity=Severity.MEDIUM,
                title="M1",
                description="D",
                location=FindingLocation(file_path="a", start_line=3, end_line=3),
                evidence="e",
                remediation="r",
            ),
        ]
        summary = FindingSummary.from_findings(findings)
        assert summary.high == 2
        assert summary.medium == 1
        assert summary.critical == 0
        assert summary.total == 3
