"""BlockSecScan Public API Layer."""

from blocksec.core.engine import CoreEngine
from blocksec.models.scan import ScanResult, ScanTarget, ScanTargetType

__all__ = ["scan_fabric"]


def scan_fabric(path: str = ".") -> ScanResult:
    target = ScanTarget(target_type=ScanTargetType.FABRIC_CONFIG, path=path)
    engine = CoreEngine()
    return engine.scan(target)
