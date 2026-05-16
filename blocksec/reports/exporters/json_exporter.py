import json

from blocksec.models.scan import ScanResult


class JsonExporter:
    @staticmethod
    def export(result: ScanResult, indent: int = 2) -> str:
        return json.dumps(result.model_dump(mode="json"), indent=indent, ensure_ascii=False)
