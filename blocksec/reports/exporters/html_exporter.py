import os

from jinja2 import Environment, FileSystemLoader

from blocksec.models.scan import ScanResult

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


class HtmlExporter:
    @staticmethod
    def export(result: ScanResult) -> str:
        try:
            env = Environment(loader=FileSystemLoader(_TEMPLATE_DIR))
            template = env.get_template("report.html.jinja2")
            return template.render(result=result)
        except Exception:
            return _fallback_html(result)


def _fallback_html(result: ScanResult) -> str:
    s = result.summary
    rows = "".join(
        f"<tr><td>{f.severity.value}</td><td>{f.rule_id}</td><td>{f.title}</td><td>{f.file_path}</td></tr>"
        for f in sorted(result.findings, key=lambda x: x.severity.value, reverse=True)
    )
    return f"""<!DOCTYPE html>
<html><head><meta charset=\"utf-8\"><title>BlockSecScan Report</title></head>
<body><h1>BlockSecScan Report</h1>
<p>Target: {result.target.path} | Duration: {result.duration_seconds:.1f}s</p>
<p>Critical:{s.critical} High:{s.high} Medium:{s.medium} Low:{s.low} Info:{s.info}</p>
<table border=\"1\"><tr><th>Severity</th><th>Rule</th><th>Title</th><th>File</th></tr>
{rows}</table></body></html>"""
