import json
import logging
import time
import uuid

from mitmproxy import http

logger = logging.getLogger("aegis-proxy")


def generate_request_id() -> str:
    return f"req_{uuid.uuid4().hex[:12]}"


def block_flow(flow: http.HTTPFlow, reason: str, request_id: str, pattern_matched: str | None = None) -> None:
    """Set 403 response on flow and emit structured log."""
    body = json.dumps({
        "request_id": request_id,
        "action": "block",
        "reason": reason,
        "url": flow.request.pretty_url,
    })
    flow.response = http.Response.make(
        403,
        body.encode(),
        {"Content-Type": "application/json", "X-Aegis-Request-Id": request_id},
    )

    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "request_id": request_id,
        "action": "block",
        "reason": reason,
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "source": "aegis-proxy",
    }
    if pattern_matched:
        event["pattern_matched"] = pattern_matched
    logger.warning("%s", json.dumps(event))
