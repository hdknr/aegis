import logging
import os

import httpx

from scanner.models import Verdict

logger = logging.getLogger("aegis-proxy")

SCANNER_URL = os.getenv("AEGIS_SCANNER_URL", "http://aegis-scanner:8080")
SCAN_TIMEOUT = int(os.getenv("AEGIS_SCAN_TIMEOUT_MS", "30000")) / 1000


def scan_payload(content: bytes, content_type: str, source_url: str, request_id: str) -> Verdict:
    """POST payload to scanner. Returns Verdict; defaults to block on any error."""
    try:
        resp = httpx.post(
            f"{SCANNER_URL}/scan",
            files={"file": ("payload", content, "application/octet-stream")},
            data={
                "content_type": content_type,
                "source_url": source_url,
                "request_id": request_id,
            },
            timeout=SCAN_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        try:
            verdict = Verdict(data.get("verdict", "block"))
        except ValueError:
            verdict = Verdict.block
        logger.info("Scan result for %s: %s (request_id=%s)", source_url, verdict, request_id)
        return verdict
    except httpx.TimeoutException:
        logger.error("Scanner timeout for %s (request_id=%s)", source_url, request_id)
        return Verdict.block
    except Exception as e:
        logger.error("Scanner error for %s: %s (request_id=%s)", source_url, e, request_id)
        return Verdict.block
