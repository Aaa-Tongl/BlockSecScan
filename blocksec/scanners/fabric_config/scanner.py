from blocksec.models.finding import Finding
from blocksec.models.rule import Rule
from blocksec.models.scan import ScanTarget
from blocksec.rule_engine.engine import RuleEngine
from blocksec.scanners.base import BaseScanner
from blocksec.scanners.fabric_config.file_discovery import discover_files


class FabricConfigScanner(BaseScanner):
    def can_handle(self, target: ScanTarget) -> bool:
        return target.target_type == "fabric_config"

    def scan(self, target: ScanTarget, rules: list[Rule]) -> list[Finding]:
        files = discover_files(target.path)
        findings: list[Finding] = []

        for file_path in files:
            content = self._read_file(file_path)
            if content is None:
                continue

            for rule in rules:
                if not rule.enabled:
                    continue
                finding = RuleEngine.match_file(file_path, content, rule)
                if finding:
                    findings.append(finding)

        return findings

    @staticmethod
    def _read_file(file_path: str) -> str | None:
        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except (OSError, PermissionError):
            return None
