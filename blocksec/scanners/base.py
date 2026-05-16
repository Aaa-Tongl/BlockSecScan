from abc import ABC, abstractmethod

from blocksec.models.finding import Finding
from blocksec.models.rule import Rule
from blocksec.models.scan import ScanTarget


class BaseScanner(ABC):
    @abstractmethod
    def can_handle(self, target: ScanTarget) -> bool: ...

    @abstractmethod
    def scan(self, target: ScanTarget, rules: list[Rule]) -> list[Finding]: ...
