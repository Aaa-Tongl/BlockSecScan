from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from blocksec.models.finding import Finding, Severity


class ScanTargetType(StrEnum):
    FABRIC_CONFIG = "fabric_config"
    FABRIC_RUNTIME = "fabric_runtime"
    CHAINCODE = "chaincode"
    CONTRACT = "contract"
    RPC = "rpc"
    WEB3 = "web3"


class ScanTarget(BaseModel):
    target_type: ScanTargetType = ScanTargetType.FABRIC_CONFIG
    path: str = "."
    host: str = ""
    options: dict[str, Any] = Field(default_factory=dict)


class FindingSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> FindingSummary:
        summary = cls()
        for f in findings:
            if f.severity == Severity.CRITICAL:
                summary.critical += 1
            elif f.severity == Severity.HIGH:
                summary.high += 1
            elif f.severity == Severity.MEDIUM:
                summary.medium += 1
            elif f.severity == Severity.LOW:
                summary.low += 1
            elif f.severity == Severity.INFO:
                summary.info += 1
        return summary


class ScanResult(BaseModel):
    scan_id: UUID = Field(default_factory=uuid4)
    target: ScanTarget
    timestamp: datetime = Field(default_factory=datetime.now)
    findings: list[Finding] = Field(default_factory=list)
    summary: FindingSummary = Field(default_factory=FindingSummary)
    duration_seconds: float = 0.0
    errors: list[str] = Field(default_factory=list)
