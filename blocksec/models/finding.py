from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4

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


class FindingLocation(BaseModel):
    file_path: str
    start_line: int
    end_line: int


class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    rule_id: str
    severity: Severity
    category: Category = Category.FABRIC_CONFIG
    title: str
    description: str
    location: FindingLocation
    evidence: str
    remediation: str
    references: list[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    scanner_name: str = ""
    rule_version: str = ""
    fix_available: bool = True
    detected_at: datetime = Field(default_factory=datetime.now)
