import os

from jinja2 import Environment, FileSystemLoader

from blocksec.models.scan import ScanResult

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


class HtmlExporter:
    @staticmethod
    def export(result: ScanResult) -> str:
        env = Environment(loader=FileSystemLoader(_TEMPLATE_DIR))
        template = env.get_template("report.html.jinja2")
        return template.render(result=result)
