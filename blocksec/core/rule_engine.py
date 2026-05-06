import re

from blocksec.models.rule import MatchCondition, MatchType, Rule


class RuleEngine:
    """规则执行引擎：根据 Rule 的匹配条件，在文本中查找匹配。"""

    def match_file(self, rule: Rule, file_path: str, content: str) -> list[tuple[int, int, str]]:
        """对单个文件执行单条规则匹配，返回 (start_line, end_line, 匹配文本) 列表。"""
        if not rule.enabled:
            return []

        if not self._file_matches(rule, file_path):
            return []

        match = rule.match
        if match.type == MatchType.PATTERN:
            return self._match_pattern(content, match)
        elif match.type == MatchType.REGEX:
            return self._match_regex(content, match)
        elif match.type == MatchType.KEY_VALUE:
            return self._match_key_value(content, match)
        else:
            return []

    def _file_matches(self, rule: Rule, file_path: str) -> bool:
        """检查文件名是否匹配规则指定的 file_pattern。"""
        import fnmatch
        import os

        file_name = os.path.basename(file_path)
        pattern = rule.match.file_pattern
        if pattern == "*":
            return True
        return fnmatch.fnmatch(file_name, pattern)

    def _match_pattern(self, content: str, match: MatchCondition) -> list[tuple[int, int, str]]:
        """字符串包含匹配。"""
        if not match.pattern:
            return []

        results: list[tuple[int, int, str]] = []
        lines = content.splitlines()

        search_pattern = match.pattern if match.case_sensitive else match.pattern.lower()

        for i, line in enumerate(lines, start=1):
            search_line = line if match.case_sensitive else line.lower()

            match_found = not match.negate if search_pattern in search_line else match.negate

            if match_found:
                results.append((i, i, line.strip()))

        return results

    def _match_regex(self, content: str, match: MatchCondition) -> list[tuple[int, int, str]]:
        """正则匹配。"""
        if not match.regex:
            return []

        flags = 0 if match.case_sensitive else re.IGNORECASE
        try:
            compiled = re.compile(match.regex, flags)
        except re.error:
            return []

        results: list[tuple[int, int, str]] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, start=1):
            match_found = not match.negate if compiled.search(line) else match.negate

            if match_found:
                results.append((i, i, line.strip()))

        return results

    def _match_key_value(self, content: str, match: MatchCondition) -> list[tuple[int, int, str]]:
        """Key-Value 匹配（用于 .env 和 docker-compose 环境变量）。"""
        if not match.key:
            return []

        results: list[tuple[int, int, str]] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()

            if "=" not in stripped:
                continue

            kv_part = stripped[2:] if stripped.startswith("- ") else stripped

            if "=" not in kv_part:
                continue

            key, _, val = kv_part.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")

            target_key = match.key if match.case_sensitive else match.key.lower()
            check_key = key if match.case_sensitive else key.lower()

            if target_key != check_key:
                continue

            if match.value is not None:
                target_val = match.value if match.case_sensitive else match.value.lower()
                check_val = val if match.case_sensitive else val.lower()

                if match.negate:
                    if target_val != check_val:
                        results.append((i, i, stripped))
                else:
                    if target_val == check_val:
                        results.append((i, i, stripped))
            else:
                results.append((i, i, stripped))

        return results
