"""Scanner abstract base class and registry."""

from abc import ABC, abstractmethod

from blocksec.models.finding import Finding


class BaseScanner(ABC):
    """所有扫描器必须实现的抽象基类。"""

    name: str = "base"
    description: str = ""

    @abstractmethod
    def can_handle(self, target_type: str) -> bool:
        """判断此扫描器是否能处理给定的目标类型。"""
        ...

    @abstractmethod
    def scan(self, target_path: str) -> list[Finding]:
        """执行扫描，返回 Finding 列表。"""
        ...
