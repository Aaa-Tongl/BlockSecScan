import time

from blocksec.core.registry import ScannerRegistry
from blocksec.models.finding import Finding
from blocksec.models.scan import ScanResult, ScanSummary, ScanTarget
from blocksec.rule_engine.parser import RuleParser


class CoreEngine:
    def __init__(self, registry: ScannerRegistry, rules_dir: str):
        self.registry = registry
        self.rules_dir = rules_dir

    def scan(self, target: ScanTarget) -> ScanResult:
        start = time.time()

        scanner = self.registry.get_scanner(target)
        if scanner is None:
            return ScanResult(
                target=target,
                findings=[],
                duration_seconds=time.time() - start,
            )

        rules = RuleParser.load_rules(self.rules_dir, category=target.target_type)
        if not rules and target.target_type == "fabric_runtime":
            rules = RuleParser.load_rules(self.rules_dir, category="fabric_config")
        findings = scanner.scan(target, rules)
        summary = self._build_summary(findings)

        return ScanResult(
            target=target,
            findings=findings,
            summary=summary,
            duration_seconds=round(time.time() - start, 2),
        )

    @staticmethod
    def _build_summary(findings: list[Finding]) -> ScanSummary:
        counts = dict.fromkeys(["critical", "high", "medium", "low", "info"], 0)
        for f in findings:
            counts[f.severity.value.lower()] += 1
        return ScanSummary(**counts, total=len(findings))
