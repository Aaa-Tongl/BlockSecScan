from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from blocksec.models.finding import Severity


class MatchType(StrEnum):
    PATTERN = "pattern"
    KEY_VALUE = "key_value"
    REGEX = "regex"
    MULTI_FILE = "multi_file"


class MatchCondition(BaseModel):
    type: MatchType = MatchType.PATTERN
    file_pattern: str = "*"
    pattern: str | None = None
    key: str | None = None
    value: str | None = None
    regex: str | None = None
    case_sensitive: bool = False
    negate: bool = False


class TargetSpec(BaseModel):
    type: str = ""
    files: list[str] = Field(default_factory=list)
    directories: list[str] = Field(default_factory=list)


class Rule(BaseModel):
    id: str
    name: str
    category: str
    severity: Severity
    version: str = "1.0.0"
    target: TargetSpec = Field(default_factory=TargetSpec)
    match: MatchCondition
    description: str
    remediation: str
    references: list[str] = Field(default_factory=list)
    false_positive_note: str = ""
    enabled: bool = True
