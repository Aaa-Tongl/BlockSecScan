import time
from pathlib import Path

from blocksec.models.finding import Finding
from blocksec.models.scan import FindingSummary, ScanResult, ScanTarget
from blocksec.scanners.base import BaseScanner
from blocksec.scanners.fabric_config.scanner import FabricConfigScanner
from blocksec.scanners.fabric_runtime.scanner import FabricRuntimeScanner


class CoreEngine:
    """BlockSecScan 核心扫描引擎。"""

    def __init__(self, rules_dir: str | None = None):
        self._scanners: list[BaseScanner] = []
        self._rules_dir = rules_dir

        self._register_default_scanners()

    def _register_default_scanners(self) -> None:
        rules_dir = self._rules_dir or str(Path(__file__).parent.parent / "rules")

        config_scanner = FabricConfigScanner(rules_dir=str(Path(rules_dir) / "fabric"))
        self._scanners.append(config_scanner)

        runtime_scanner = FabricRuntimeScanner()
        self._scanners.append(runtime_scanner)

    def register_scanner(self, scanner: BaseScanner) -> None:
        self._scanners.append(scanner)

    def get_scanner(self, target_type: str) -> BaseScanner | None:
        for scanner in self._scanners:
            if scanner.can_handle(target_type):
                return scanner
        return None

    def scan(self, target: ScanTarget) -> ScanResult:
        start_time = time.perf_counter()
        errors: list[str] = []
        all_findings: list[Finding] = []

        scanner = self.get_scanner(target.target_type)
        if scanner is None:
            errors.append(f"No scanner found for target type: {target.target_type}")
        else:
            try:
                all_findings = scanner.scan(target.path)
            except Exception as e:
                errors.append(f"Scanner '{scanner.name}' error: {e}")

        duration = round(time.perf_counter() - start_time, 3)
        summary = FindingSummary.from_findings(all_findings)
        result = ScanResult(
            target=target,
            findings=all_findings,
            summary=summary,
            duration_seconds=duration,
            errors=errors,
        )
        return result
