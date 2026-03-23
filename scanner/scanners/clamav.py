import subprocess
from pathlib import Path

from scanner.config import CLAMD_HOST, CLAMD_PORT, SCAN_TIMEOUT
from scanner.models import ScanDetail, Verdict


def scan(file_path: Path) -> tuple[Verdict, ScanDetail]:
    try:
        result = subprocess.run(
            ["clamdscan", "--stream", f"--stream-host={CLAMD_HOST}", f"--stream-port={CLAMD_PORT}",
             "--no-summary", str(file_path)],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT / 1000,
        )
    except subprocess.TimeoutExpired:
        return Verdict.block, ScanDetail(scanner="clamav", result="TIMEOUT")
    except FileNotFoundError:
        return Verdict.block, ScanDetail(scanner="clamav", result="ERROR", threat="clamdscan not found")

    output = result.stdout.strip()

    if result.returncode == 1:
        # Virus found — parse threat name from output like "file: ThreatName FOUND"
        threat = "unknown"
        if "FOUND" in output:
            parts = output.rsplit(":", 1)
            if len(parts) == 2:
                threat = parts[1].strip().removesuffix("FOUND").strip()
        return Verdict.block, ScanDetail(scanner="clamav", result="INFECTED", threat=threat)

    if result.returncode == 0:
        return Verdict.allow, ScanDetail(scanner="clamav", result="OK")

    # Any other return code is an error — fail-closed
    return Verdict.block, ScanDetail(
        scanner="clamav", result="ERROR", threat=output or result.stderr.strip()
    )
