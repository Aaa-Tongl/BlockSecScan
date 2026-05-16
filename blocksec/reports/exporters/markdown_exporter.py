from blocksec.models.scan import ScanResult


class MarkdownExporter:
    @staticmethod
    def export(result: ScanResult) -> str:
        s = result.summary
        lines = [
            "# BlockSecScan Report",
            "",
            f"**Scan ID:** `{result.scan_id}`",
            f"**Target:** {result.target.path}",
            f"**Date:** {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Duration:** {result.duration_seconds:.1f}s",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| Critical | {s.critical} |",
            f"| High     | {s.high} |",
            f"| Medium   | {s.medium} |",
            f"| Low      | {s.low} |",
            f"| Info     | {s.info} |",
            f"| **Total**| **{s.total}** |",
            "",
        ]

        if not result.findings:
            lines.append("No security issues found.")
            return "\n".join(lines)

        lines.append("## Findings")
        lines.append("")

        for f in sorted(result.findings, key=lambda x: x.severity.value, reverse=True):
            lines.append(f"### [{f.severity.value}] {f.title}")
            lines.append("")
            lines.append(f"- **Rule:** `{f.rule_id}`")
            lines.append(f"- **File:** `{f.file_path}`")
            if f.line_start:
                lines.append(f"- **Line:** {f.line_start}")
            lines.append(f"- **Confidence:** {f.confidence:.0%}")
            lines.append("")
            lines.append(f"**Description:** {f.description}")
            lines.append("")
            lines.append("**Evidence:**")
            lines.append("```")
            lines.append(f.evidence)
            lines.append("```")
            lines.append("")
            lines.append(f"**Remediation:** {f.remediation}")
            if f.references:
                lines.append("")
                lines.append("**References:**")
                for ref in f.references:
                    lines.append(f"- {ref}")
            lines.append("")

        return "\n".join(lines)
