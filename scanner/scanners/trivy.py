import json
import subprocess
from pathlib import Path

from scanner.config import SCAN_TIMEOUT
from scanner.models import ScanDetail, Verdict
from scanner.scanners import VERDICT_PRIORITY

_SEVERITY_TO_VERDICT = {
    "CRITICAL": Verdict.block,
    "HIGH": Verdict.block,
    "MEDIUM": Verdict.warn,
    "LOW": Verdict.allow,
    "UNKNOWN": Verdict.allow,
}


def scan(file_path: Path) -> tuple[Verdict, ScanDetail]:
    try:
        result = subprocess.run(
            ["trivy", "fs", "--scanners", "vuln", "--format", "json",
             "--skip-db-update", "--quiet", str(file_path)],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT / 1000,
        )
    except subprocess.TimeoutExpired:
        return Verdict.block, ScanDetail(scanner="trivy", result="TIMEOUT")
    except FileNotFoundError:
        return Verdict.block, ScanDetail(scanner="trivy", result="ERROR", threat="trivy not found")

    if result.returncode not in (0, 1):
        return Verdict.block, ScanDetail(
            scanner="trivy", result="ERROR", threat=result.stderr.strip()
        )

    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return Verdict.block, ScanDetail(scanner="trivy", result="ERROR", threat="invalid JSON output")

    vulnerabilities = []
    worst_verdict = Verdict.allow
    worst_severity = "NONE"

    for res in data.get("Results", []):
        for vuln in res.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "UNKNOWN").upper()
            vuln_verdict = _SEVERITY_TO_VERDICT.get(severity, Verdict.allow)
            if VERDICT_PRIORITY[vuln_verdict] > VERDICT_PRIORITY[worst_verdict]:
                worst_verdict = vuln_verdict
                worst_severity = severity
            vulnerabilities.append({
                "id": vuln.get("VulnerabilityID", ""),
                "severity": severity,
                "description": vuln.get("Title", vuln.get("Description", "")),
            })

    if not vulnerabilities:
        return Verdict.allow, ScanDetail(scanner="trivy", result="NO_VULNERABILITIES")

    return worst_verdict, ScanDetail(
        scanner="trivy", result=worst_severity, vulnerabilities=vulnerabilities
    )
