from blocksec.models.scan import ScanTarget
from blocksec.scanners.base import BaseScanner


class ScannerRegistry:
    def __init__(self):
        self._scanners: list[BaseScanner] = []

    def register(self, scanner: BaseScanner) -> None:
        self._scanners.append(scanner)

    def get_scanner(self, target: ScanTarget) -> BaseScanner | None:
        for scanner in self._scanners:
            if scanner.can_handle(target):
                return scanner
        return None

    def list_scanners(self) -> list[str]:
        return [s.__class__.__name__ for s in self._scanners]
