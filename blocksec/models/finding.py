import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(StrEnum):
    FABRIC_CONFIG = "FABRIC_CONFIG"
    FABRIC_RUNTIME = "FABRIC_RUNTIME"
    CHAINCODE = "CHAINCODE"
    CONTRACT = "CONTRACT"
    RPC = "RPC"
    WEB3 = "WEB3"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    severity: Severity
    category: Category
    title: str
    description: str
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    evidence: str
    remediation: str
    references: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    false_positive_note: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
