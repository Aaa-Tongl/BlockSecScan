from pathlib import Path

import yaml

from blocksec.models.finding import Severity
from blocksec.models.rule import MatchCondition, MatchType, Rule, TargetSpec


class RuleParser:
    """解析 YAML 规则文件，返回 Rule 对象列表。"""

    def load_rules(self, rules_dir: str | Path) -> list[Rule]:
        rules_dir = Path(rules_dir)
        if not rules_dir.is_dir():
            return []

        rules: list[Rule] = []
        for yaml_file in sorted(rules_dir.rglob("*.yaml")):
            loaded = self._load_single_file(yaml_file)
            if loaded is not None:
                rules.extend(loaded)
        return rules

    def load_rule(self, file_path: str | Path) -> Rule | None:
        result = self._load_single_file(Path(file_path))
        if result:
            return result[0]
        return None

    def _load_single_file(self, file_path: Path) -> list[Rule] | None:
        try:
            with open(file_path, encoding="utf-8") as f:
                raw = f.read()
        except OSError as e:
            print(f"Warning: Failed to read {file_path}: {e}")
            return None

        documents: list[dict] = []
        try:
            docs = yaml.safe_load_all(raw)
            for doc in docs:
                if isinstance(doc, dict):
                    documents.append(doc)
                elif isinstance(doc, list):
                    documents.extend(doc)
        except yaml.YAMLError as e:
            print(f"Warning: Failed to parse {file_path}: {e}")
            return None

        if not documents:
            return None

        results: list[Rule] = []
        for item in documents:
            try:
                rule = self._parse_rule_dict(item, file_path)
                results.append(rule)
            except (KeyError, ValueError) as e:
                print(f"Warning: Invalid rule in {file_path}: {e}")
                continue

        return results if results else None

    def _parse_rule_dict(self, data: dict, file_path: Path) -> Rule:
        target_data = data.get("target", {})
        target = TargetSpec(
            type=target_data.get("type", ""),
            files=target_data.get("files", []),
            directories=target_data.get("directories", []),
        )

        match_data = data.get("match", {})
        match_condition = MatchCondition(
            type=MatchType(match_data.get("type", "pattern")),
            file_pattern=match_data.get("file_pattern", "*"),
            pattern=match_data.get("pattern"),
            key=match_data.get("key"),
            value=str(match_data.get("value", "")) if match_data.get("value") is not None else None,
            regex=match_data.get("regex"),
            case_sensitive=match_data.get("case_sensitive", False),
            negate=match_data.get("negate", False),
        )

        return Rule(
            id=data["id"],
            name=data["name"],
            category=data.get("category", "Fabric Configuration"),
            severity=Severity(data.get("severity", "INFO")),
            version=data.get("version", "1.0.0"),
            target=target,
            match=match_condition,
            description=data.get("description", ""),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            false_positive_note=data.get("false_positive_note", ""),
            enabled=data.get("enabled", True),
        )
