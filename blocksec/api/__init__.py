"""BlockSecScan Public API Layer."""

from blocksec.core.engine import CoreEngine
from blocksec.models.scan import ScanResult, ScanTarget, ScanTargetType

__all__ = ["scan_fabric", "scan_fabric_runtime"]


def _scan(target_type: ScanTargetType, path: str) -> ScanResult:
    target = ScanTarget(target_type=target_type, path=path)
    engine = CoreEngine()
    return engine.scan(target)


def scan_fabric(path: str = ".") -> ScanResult:
    return _scan(ScanTargetType.FABRIC_CONFIG, path)


def scan_fabric_runtime(path: str = ".") -> ScanResult:
    return _scan(ScanTargetType.FABRIC_RUNTIME, path)
