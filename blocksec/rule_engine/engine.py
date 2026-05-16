import re
from pathlib import Path

import yaml

from blocksec.models.finding import Category, Finding, Severity
from blocksec.models.rule import Rule


class RuleEngine:
    SUPPORTED_MATCH_TYPES = {"regex", "contains", "yaml_path", "file_name", "certificate"}

    SEVERITY_MAP = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }
    CATEGORY_MAP = {
        "fabric_config": Category.FABRIC_CONFIG,
        "fabric_runtime": Category.FABRIC_RUNTIME,
        "chaincode": Category.CHAINCODE,
        "contract": Category.CONTRACT,
        "rpc": Category.RPC,
        "web3": Category.WEB3,
    }
    CONFIDENCE_MAP = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}

    @staticmethod
    def match_file(file_path: str, content: str, rule: Rule) -> Finding | None:
        if not rule.enabled:
            return None

        match_type = rule.match.type
        if match_type not in RuleEngine.SUPPORTED_MATCH_TYPES:
            return None

        handler = getattr(RuleEngine, f"_match_{match_type}", None)
        if handler is None:
            return None

        return handler(file_path, content, rule)

    @staticmethod
    def _match_regex(file_path: str, content: str, rule: Rule) -> Finding | None:
        pattern = rule.match.pattern
        if not pattern:
            return None

        flags = 0 if rule.match.case_sensitive else re.IGNORECASE
        try:
            compiled = re.compile(pattern, flags)
        except re.error:
            return None

        for i, line in enumerate(content.splitlines(), start=1):
            m = compiled.search(line)
            if m:
                return RuleEngine._build_finding(file_path, i, i, line.strip(), rule)

        return None

    @staticmethod
    def _match_contains(file_path: str, content: str, rule: Rule) -> Finding | None:
        pattern = rule.match.pattern
        if not pattern:
            return None

        check_content = content if rule.match.case_sensitive else content.lower()
        check_pattern = pattern if rule.match.case_sensitive else pattern.lower()

        if check_pattern in check_content:
            for i, line in enumerate(content.splitlines(), start=1):
                pl = line if rule.match.case_sensitive else line.lower()
                if (pattern if rule.match.case_sensitive else pattern.lower()) in pl:
                    return RuleEngine._build_finding(file_path, i, i, line.strip(), rule)

        return None

    @staticmethod
    def _match_yaml_path(file_path: str, content: str, rule: Rule) -> Finding | None:
        pattern = rule.match.pattern
        if not pattern:
            return None

        try:
            parsed = yaml.safe_load(content)
        except yaml.YAMLError:
            return None

        keys = pattern.split(".")
        value = parsed
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None

        expected = rule.match.patterns
        if not expected:
            if value is not None:
                return RuleEngine._build_finding(file_path, 1, 1, f"{pattern}: {value}", rule)
            return None

        if str(value).lower() == str(expected[0]).lower():
            return RuleEngine._build_finding(file_path, 1, 1, f"{pattern}: {value}", rule)

        return None

    @staticmethod
    def _match_file_name(file_path: str, content: str, rule: Rule) -> Finding | None:
        pattern = rule.match.pattern
        if not pattern:
            return None

        fname = Path(file_path).name
        flags = 0 if rule.match.case_sensitive else re.IGNORECASE

        if re.search(pattern, fname, flags):
            return RuleEngine._build_finding(file_path, 1, 1, fname, rule)

        return None

    @staticmethod
    def _match_certificate(file_path: str, content: str, rule: Rule) -> Finding | None:
        from blocksec.utils.cert_check import (
            get_cert_info,
            load_certificate,
        )

        cert = load_certificate(file_path)
        if cert is None:
            return None

        info = get_cert_info(cert)
        issues: list[str] = []

        if info["expired"]:
            issues.append(f"Certificate expired. Not after: {info['not_after']}")
        elif info["expiring_soon"]:
            issues.append(f"Certificate expiring soon ({info['days_remaining']} days). Not after: {info['not_after']}")

        algo = info["algorithm"]
        if algo["issues"]:
            issues.extend(algo["issues"])

        if not issues:
            return None

        severity = "HIGH" if info["expired"] else "MEDIUM"
        evidence = f"Subject: {info['subject_cn']} | Issuer: {info['issuer_cn']} | Expires: {info['not_after']}"

        return Finding(
            rule_id=rule.id,
            severity=RuleEngine.SEVERITY_MAP.get(severity, Severity.MEDIUM),
            category=RuleEngine.CATEGORY_MAP.get(rule.category, Category.FABRIC_CONFIG),
            title=f"{rule.name}: {'; '.join(issues)}",
            description=rule.description,
            file_path=file_path,
            line_start=1,
            line_end=1,
            evidence=evidence,
            remediation=rule.remediation,
            references=rule.references,
            confidence=RuleEngine.CONFIDENCE_MAP.get(rule.confidence.upper(), 0.9),
            false_positive_note=rule.false_positive_note,
        )

    @staticmethod
    def _build_finding(file_path: str, line_start: int, line_end: int, evidence: str, rule: Rule) -> Finding:
        return Finding(
            rule_id=rule.id,
            severity=RuleEngine.SEVERITY_MAP.get(rule.severity.upper(), Severity.INFO),
            category=RuleEngine.CATEGORY_MAP.get(rule.category, Category.FABRIC_CONFIG),
            title=rule.name,
            description=rule.description,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            evidence=evidence,
            remediation=rule.remediation,
            references=rule.references,
            confidence=RuleEngine.CONFIDENCE_MAP.get(rule.confidence.upper(), 0.7),
            false_positive_note=rule.false_positive_note,
        )
