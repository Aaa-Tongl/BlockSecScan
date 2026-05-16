from pydantic import BaseModel, Field


class MatchConfig(BaseModel):
    type: str  # regex | contains | yaml_path | file_name
    pattern: str = ""
    patterns: list[str] = Field(default_factory=list)
    file_pattern: str = ""
    case_sensitive: bool = False


class Rule(BaseModel):
    id: str
    name: str
    category: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: str = "HIGH"  # HIGH | MEDIUM | LOW
    version: str = "1.0.0"
    target: dict = Field(default_factory=dict)
    match: MatchConfig
    description: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    false_positive_note: str = ""
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True
