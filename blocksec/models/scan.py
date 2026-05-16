import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from blocksec.models.finding import Finding


class ScanTarget(BaseModel):
    target_type: str  # fabric_config | fabric_runtime | contract | rpc | web3
    path: str
    options: dict = Field(default_factory=dict)


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: ScanTarget
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    findings: list[Finding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    duration_seconds: float = 0.0
