import socket
import struct
from pathlib import Path

from scanner.config import CLAMD_HOST, CLAMD_PORT, SCAN_TIMEOUT
from scanner.models import ScanDetail, Verdict

_CHUNK_SIZE = 8192


def scan(file_path: Path) -> tuple[Verdict, ScanDetail]:
    """Scan a file by streaming it to clamd via TCP INSTREAM command."""
    try:
        with socket.create_connection((CLAMD_HOST, CLAMD_PORT), timeout=SCAN_TIMEOUT / 1000) as sock:
            sock.sendall(b"zINSTREAM\0")

            with open(file_path, "rb") as f:
                while chunk := f.read(_CHUNK_SIZE):
                    sock.sendall(struct.pack("!L", len(chunk)) + chunk)
            # Send terminating zero-length chunk
            sock.sendall(struct.pack("!L", 0))

            response = b""
            while data := sock.recv(4096):
                response += data

    except (TimeoutError, socket.timeout):
        return Verdict.block, ScanDetail(scanner="clamav", result="TIMEOUT")
    except (ConnectionRefusedError, OSError) as e:
        return Verdict.block, ScanDetail(scanner="clamav", result="ERROR", threat=str(e))

    result_str = response.decode("utf-8", errors="replace").strip().rstrip("\0")

    # clamd INSTREAM response format: "stream: OK" or "stream: ThreatName FOUND"
    if result_str.endswith("OK"):
        return Verdict.allow, ScanDetail(scanner="clamav", result="OK")

    if "FOUND" in result_str:
        # Parse "stream: Win.Trojan.Agent-123 FOUND"
        parts = result_str.rsplit(":", 1)
        threat = parts[1].strip().removesuffix("FOUND").strip() if len(parts) == 2 else "unknown"
        return Verdict.block, ScanDetail(scanner="clamav", result="INFECTED", threat=threat)

    # Any other response — fail-closed
    return Verdict.block, ScanDetail(scanner="clamav", result="ERROR", threat=result_str)
