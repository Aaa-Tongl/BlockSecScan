import os

from blocksec.config import settings
from blocksec.core.engine import CoreEngine
from blocksec.core.registry import ScannerRegistry
from blocksec.models.rule import Rule
from blocksec.models.scan import ScanResult, ScanTarget
from blocksec.rule_engine.parser import RuleParser
from blocksec.scanners.fabric_config.scanner import FabricConfigScanner
from blocksec.scanners.fabric_runtime.scanner import FabricRuntimeScanner
from blocksec.scanners.rpc.scanner import RpcScanner
from blocksec.scanners.smart_contract.scanner import SmartContractScanner
from blocksec.scanners.web3.scanner import Web3Scanner

_engine: CoreEngine | None = None


def _get_engine() -> CoreEngine:
    global _engine
    if _engine is None:
        registry = ScannerRegistry()
        registry.register(FabricConfigScanner())
        registry.register(FabricRuntimeScanner())
        registry.register(SmartContractScanner())
        registry.register(RpcScanner())
        registry.register(Web3Scanner())
        _engine = CoreEngine(registry, settings.resolved_rules_dir)
    return _engine


def scan(target: ScanTarget) -> ScanResult:
    return _get_engine().scan(target)


def list_rules(category: str | None = None) -> list[Rule]:
    return RuleParser.load_rules(settings.resolved_rules_dir, category=category)


def generate_report(result: ScanResult, fmt: str = "json", output_path: str | None = None) -> str:
    if fmt == "json":
        from blocksec.reports.exporters.json_exporter import JsonExporter

        report = JsonExporter.export(result)
    elif fmt == "markdown":
        from blocksec.reports.exporters.markdown_exporter import MarkdownExporter

        report = MarkdownExporter.export(result)
    elif fmt == "html":
        from blocksec.reports.exporters.html_exporter import HtmlExporter

        report = HtmlExporter.export(result)
    elif fmt == "sarif":
        from blocksec.reports.exporters.sarif_exporter import SarifExporter

        report = SarifExporter.export(result)
    else:
        raise ValueError(f"Unsupported report format: {fmt}")

    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)

    return report
