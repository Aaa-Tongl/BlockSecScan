"""Slither subprocess runner and output parser."""

import json
import os
import subprocess

from blocksec.models.finding import Category, Finding, Severity
from blocksec.scanners.smart_contract.owasp_map import map_detector_to_owasp

SLITHER_SEVERITY_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Optimization": Severity.INFO,
}


def run_slither(project_path: str) -> list[Finding]:
    if not os.path.isdir(project_path):
        return []

    _ensure_solc_for_files(project_path)

    # Case 1+2: Single project with contracts/ or build config
    if _is_structured_project(project_path):
        return _run_slither_once([".", "--json", "-"], project_path)

    # Case 3: Flat dirs — scan each subdirectory containing .sol files
    all_findings: list[Finding] = []
    seen: set[str] = set()
    for sol_dir in _find_sol_dirs(project_path):
        findings = _run_slither_once([sol_dir, "--solc", "solc", "--json", "-"], sol_dir)
        for f in findings:
            key = f"{f.rule_id}:{f.file_path}:{f.line_start}"
            if key not in seen:
                seen.add(key)
                all_findings.append(f)
    return all_findings


def _run_slither_once(args: list[str], cwd: str) -> list[Finding]:
    cmd = ["slither", *args]
    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0 and not result.stdout.strip():
        return []
    return parse_slither_output(result.stdout, cwd)


def _is_structured_project(project_path: str) -> bool:
    if os.path.isdir(os.path.join(project_path, "contracts")):
        return True
    config_files = ["foundry.toml", "hardhat.config.js", "hardhat.config.ts", "truffle-config.js"]
    return any(os.path.isfile(os.path.join(project_path, f)) for f in config_files)


def _ensure_solc_for_files(project_path: str):
    """Switch solc to match pragma version if needed."""
    for sol_dir in _find_sol_dirs(project_path):
        for f in os.listdir(sol_dir):
            if f.endswith(".sol"):
                version = _detect_solc_version(os.path.join(sol_dir, f))
                if version:
                    subprocess.run(
                        ["solc-select", "use", version, "--always-install"],
                        capture_output=True, timeout=60,
                    )
                return


def _find_sol_dirs(root: str) -> list[str]:
    """Find unique directories containing .sol files."""
    dirs: set[str] = set()
    for dirpath, _dirnames, filenames in os.walk(root):
        for f in filenames:
            if f.endswith(".sol"):
                dirs.add(dirpath)
                break
    return sorted(dirs)


def _detect_solc_version(filepath: str) -> str | None:
    """Parse `pragma solidity ^X.Y.Z` from a .sol file to find the right solc."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                if "pragma solidity" in line:
                    import re
                    m = re.search(r'(\d+\.\d+\.\d+)', line)
                    if m:
                        return m.group(1)
    except OSError:
        pass
    return None


def parse_slither_output(stdout: str, scan_dir: str) -> list[Finding]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    detectors = data.get("results", {}).get("detectors", [])
    if not detectors:
        return []

    findings: list[Finding] = []
    for d in detectors:
        check = d.get("check", "unknown")
        owasp = map_detector_to_owasp(check)

        elements = d.get("elements", [])
        for elem in elements:
            loc = _extract_location(elem, scan_dir)
            finding = Finding(
                rule_id=f"SLITHER_{check.upper().replace('-', '_')}",
                severity=_map_severity(d.get("impact", "Medium")),
                category=Category.CONTRACT,
                title=f"[{owasp['swc']}] {d.get('description', check)}",
                description=_format_description(d, owasp),
                file_path=loc["file"],
                line_start=loc["line"],
                evidence=_extract_evidence(elem),
                remediation=d.get("recommendation", d.get("first_markdown_element", "")),
                references=[owasp["url"]] if owasp["url"] else [],
                confidence=_map_confidence(d.get("confidence", "Medium")),
            )
            findings.append(finding)

    return findings


def _extract_location(elem: dict, scan_dir: str) -> dict:
    sm = elem.get("source_mapping", {})
    filename = sm.get("filename_relative", sm.get("filename_absolute", ""))
    if not filename:
        filename = "contract.sol"
    filepath = os.path.join(scan_dir, filename)
    return {
        "file": filepath,
        "line": sm.get("lines", [1])[0] if sm.get("lines") else 1,
    }


def _extract_evidence(elem: dict) -> str:
    extra = elem.get("additional_fields", {})
    sig = extra.get("signature", "")
    expr = extra.get("expression", "")
    if sig and expr:
        return f"{sig}: {expr}"
    if sig:
        return sig
    return str(extra)[:200]


def _format_description(detector: dict, owasp: dict) -> str:
    desc = detector.get("description", "")
    impact = detector.get("impact", "")
    confidence = detector.get("confidence", "")
    parts = [desc]
    if owasp["swc"] != "N/A":
        parts.append(f"Classification: {owasp['swc']} — {owasp['title']}")
    parts.append(f"Impact: {impact} | Confidence: {confidence}")
    return "\n".join(parts)


def _map_severity(impact: str) -> Severity:
    return SLITHER_SEVERITY_MAP.get(impact, Severity.MEDIUM)


def _map_confidence(conf: str) -> float:
    conf_map = {"High": 0.9, "Medium": 0.7, "Low": 0.5}
    return conf_map.get(conf, 0.5)
