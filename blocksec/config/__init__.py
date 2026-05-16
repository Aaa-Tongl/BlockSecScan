import os


class Settings:
    def __init__(self):
        self.rules_dir: str = os.environ.get("BLOCKSEC_RULES_DIR", "")
        self.report_output_dir: str = os.environ.get("BLOCKSEC_REPORT_DIR", "./reports_output")
        self.default_report_format: str = os.environ.get("BLOCKSEC_REPORT_FORMAT", "json")
        self.scan_timeout_seconds: int = int(os.environ.get("BLOCKSEC_TIMEOUT", "300"))

    @property
    def resolved_rules_dir(self) -> str:
        if self.rules_dir:
            return self.rules_dir
        return os.path.join(os.path.dirname(__file__), "..", "rules")


settings = Settings()
