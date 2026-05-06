import os
from pathlib import Path

from blocksec.core.rule_engine import RuleEngine
from blocksec.core.rule_parser import RuleParser
from blocksec.models.finding import Category, Finding, FindingLocation, Severity
from blocksec.models.rule import Rule
from blocksec.scanners.base import BaseScanner


class FabricConfigScanner(BaseScanner):
    name = "fabric_config"
    description = "Hyperledger Fabric 配置安全扫描器"

    def __init__(self, rules_dir: str | None = None, rule_parser: RuleParser | None = None):
        self._rule_parser = rule_parser or RuleParser()
        self._rule_engine = RuleEngine()
        self._rules: list[Rule] = []

        if rules_dir:
            self._rules = self._rule_parser.load_rules(rules_dir)

    def load_rules(self, rules_dir: str) -> None:
        self._rules = self._rule_parser.load_rules(rules_dir)

    @property
    def rules(self) -> list[Rule]:
        return self._rules

    def can_handle(self, target_type: str) -> bool:
        return target_type in ("fabric_config", "fabric")

    def scan(self, target_path: str) -> list[Finding]:
        target = Path(target_path)
        if not target.exists():
            return []

        findings: list[Finding] = []
        collected_files = self._collect_files(target)

        for file_path, _relative_path in collected_files:
            try:
                content = Path(file_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for rule in self._rules:
                matches = self._rule_engine.match_file(rule, str(file_path), content)
                for start_line, end_line, evidence in matches:
                    finding = Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        category=Category.FABRIC_CONFIG,
                        title=rule.name,
                        description=rule.description,
                        location=FindingLocation(
                            file_path=str(file_path),
                            start_line=start_line,
                            end_line=end_line,
                        ),
                        evidence=evidence,
                        remediation=rule.remediation,
                        references=rule.references,
                        confidence=1.0 if rule.severity != Severity.LOW else 0.6,
                        scanner_name=self.name,
                        rule_version=rule.version,
                    )
                    findings.append(finding)

        return findings

    def _collect_files(self, target: Path) -> list[tuple[str, str]]:
        """收集需要扫描的文件，返回 (绝对路径, 相对路径) 列表。"""
        target_files = self._gather_target_files()
        results: list[tuple[str, str]] = []

        if target.is_file():
            file_name = target.name
            for pattern in target_files:
                import fnmatch

                if fnmatch.fnmatch(file_name, pattern):
                    results.append((str(target), file_name))
                    break
            return results

        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]

            for file in files:
                for pattern in target_files:
                    import fnmatch

                    if fnmatch.fnmatch(file, pattern):
                        full_path = os.path.join(root, file)
                        rel_path = os.path.relpath(full_path, target)
                        results.append((full_path, rel_path))
                        break

        return results

    def _gather_target_files(self) -> list[str]:
        """从所有规则的 target.files 中收集需要扫描的文件名模式。"""
        patterns: set[str] = set()
        for rule in self._rules:
            for f in rule.target.files:
                patterns.add(f)
        if not patterns:
            patterns.update(
                {
                    "docker-compose.yaml",
                    "docker-compose.yml",
                    ".env",
                    "core.yaml",
                    "orderer.yaml",
                    "configtx.yaml",
                }
            )
        return list(patterns)
