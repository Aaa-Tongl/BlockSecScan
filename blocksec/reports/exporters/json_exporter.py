import json
from pathlib import Path

from blocksec.models.scan import ScanResult


class JsonExporter:
    """将 ScanResult 导出为 JSON 文件。"""

    def export(
        self,
        result: ScanResult,
        output_path: str | Path,
        indent: int = 2,
    ) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "scan_id": str(result.scan_id),
            "target": {
                "type": result.target.target_type,
                "path": result.target.path,
            },
            "timestamp": result.timestamp.isoformat(),
            "duration_seconds": result.duration_seconds,
            "summary": {
                "critical": result.summary.critical,
                "high": result.summary.high,
                "medium": result.summary.medium,
                "low": result.summary.low,
                "info": result.summary.info,
                "total": result.summary.total,
            },
            "findings": [
                {
                    "id": str(f.id),
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "location": {
                        "file_path": f.location.file_path,
                        "start_line": f.location.start_line,
                        "end_line": f.location.end_line,
                    },
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "references": f.references,
                    "confidence": f.confidence,
                    "scanner_name": f.scanner_name,
                    "fix_available": f.fix_available,
                }
                for f in result.findings
            ],
            "errors": result.errors,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=indent)

        return output_path
