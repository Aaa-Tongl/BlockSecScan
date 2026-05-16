import glob
import os

import yaml

from blocksec.models.rule import MatchConfig, Rule


class RuleParser:
    @staticmethod
    def load_rules(rules_dir: str, category: str | None = None) -> list[Rule]:
        if not os.path.isdir(rules_dir):
            return []

        rules: list[Rule] = []
        yaml_files = glob.glob(os.path.join(rules_dir, "**/*.yaml"), recursive=True) + glob.glob(
            os.path.join(rules_dir, "**/*.yml"), recursive=True
        )

        for yaml_file in yaml_files:
            loaded = RuleParser._load_file(yaml_file)
            if loaded:
                for rule in loaded:
                    if category and rule.category != category:
                        continue
                    rules.append(rule)

        return rules

    @staticmethod
    def _load_file(file_path: str) -> list[Rule]:
        try:
            with open(file_path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except (yaml.YAMLError, OSError):
            return []

        if data is None:
            return []

        if isinstance(data, dict):
            data = [data]

        rules: list[Rule] = []
        for item in data:
            try:
                rule = RuleParser._parse_rule(item)
                if rule:
                    rules.append(rule)
            except (KeyError, TypeError, ValueError):
                continue

        return rules

    @staticmethod
    def _parse_rule(data: dict) -> Rule | None:
        if not data.get("id") or not data.get("match"):
            return None

        match_data = data["match"]
        match_config = MatchConfig(
            type=match_data.get("type", "regex"),
            pattern=match_data.get("pattern", match_data.get("regex", "")),
            patterns=match_data.get("patterns", []),
            file_pattern=match_data.get("file_pattern", ""),
            case_sensitive=match_data.get("case_sensitive", False),
        )

        return Rule(
            id=data["id"],
            name=data.get("name", data["id"]),
            category=data.get("category", "general"),
            severity=data.get("severity", "INFO"),
            confidence=data.get("confidence", "HIGH"),
            version=str(data.get("version", "1.0.0")),
            target=data.get("target", {}),
            match=match_config,
            description=data.get("description", ""),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            false_positive_note=data.get("false_positive_note", ""),
            tags=data.get("tags", []),
            enabled=data.get("enabled", True),
        )

    @staticmethod
    def get_categories(rules_dir: str) -> list[str]:
        categories: set[str] = set()
        for rule in RuleParser.load_rules(rules_dir):
            categories.add(rule.category)
        return sorted(categories)
