import os
from pathlib import Path

FABRIC_FILE_PATTERNS = [
    "docker-compose.yaml",
    "docker-compose.yml",
    "core.yaml",
    "orderer.yaml",
    "configtx.yaml",
    ".env",
    "*.yaml",
    "*.yml",
    "*.json",
    "*.pem",
    "*_sk",
    "*.key",
    "*.crt",
    "*.cert",
]

SKIP_DIRS = {".git", ".svn", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules"}


def discover_files(target_path: str) -> list[str]:
    root = Path(target_path).resolve()
    if not root.exists():
        return []

    files: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            if _matches_pattern(fname):
                files.append(full)

    return files


def _matches_pattern(fname: str) -> bool:
    from fnmatch import fnmatch

    return any(fnmatch(fname, pat) for pat in FABRIC_FILE_PATTERNS)
