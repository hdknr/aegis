import collections
import ipaddress
import logging
import os
import socket
import time
from pathlib import Path

from mitmproxy import http

from proxy.content_inspector import check_dangerous_patterns, is_binary_content, is_script_content
from proxy.rules_loader import load_c2_blocklist, load_domain_whitelist, load_rules
from proxy.scanner_client import scan_payload
from proxy.utils import block_flow, generate_request_id
from scanner.models import Verdict

logger = logging.getLogger("aegis-proxy")

RULES_PATH = Path(os.getenv("AEGIS_RULES_PATH", "/opt/aegis/rules"))

# Rate limiting configuration
RATE_LIMIT_REQUESTS = int(os.getenv("AEGIS_RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW = int(os.getenv("AEGIS_RATE_LIMIT_WINDOW", "60"))
MAX_RESPONSE_SIZE = int(os.getenv("AEGIS_MAX_RESPONSE_SIZE", "52428800"))  # 50MB

_BINARY_EXTENSIONS = (
    ".exe", ".msi", ".deb", ".rpm", ".pkg", ".dmg",
    ".tar.gz", ".tgz", ".tar.bz2", ".zip", ".gz", ".xz",
    ".bin", ".sh", ".run", ".appimage",
)


class AegisAddon:
    def __init__(self):
        self.domain_whitelist: set[str] = set()
        self.c2_blocklist: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.rules: dict = {}
        self._request_log: dict[str, collections.deque] = {}
        self._load_rules()

    def _load_rules(self):
        try:
            self.domain_whitelist = load_domain_whitelist(RULES_PATH / "domain_whitelist.txt")
            logger.info("Loaded %d whitelisted domains", len(self.domain_whitelist))
        except FileNotFoundError:
            logger.warning("domain_whitelist.txt not found, using empty whitelist")

        try:
            self.c2_blocklist = load_c2_blocklist(RULES_PATH / "c2_blocklist.txt")
            logger.info("Loaded %d C2 blocklist networks", len(self.c2_blocklist))
        except FileNotFoundError:
            logger.warning("c2_blocklist.txt not found, using empty blocklist")

        try:
            self.rules = load_rules(RULES_PATH / "rules.yml")
            patterns = self.rules.get("dangerous_patterns", [])
            logger.info("Loaded %d dangerous patterns", len(patterns))
        except FileNotFoundError:
            logger.warning("rules.yml not found, using empty rules")

    def _is_c2_ip(self, host: str) -> bool:
        try:
            addrs = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            return False

        for _, _, _, _, sockaddr in addrs:
            ip = ipaddress.ip_address(sockaddr[0])
            for network in self.c2_blocklist:
                if ip in network:
                    return True
        return False

    def _is_binary_download(self, flow: http.HTTPFlow) -> bool:
        path = flow.request.path.lower()
        return any(path.endswith(ext) for ext in _BINARY_EXTENSIONS)

    def _is_rate_limited(self, client_ip: str) -> bool:
        now = time.monotonic()
        if client_ip not in self._request_log:
            self._request_log[client_ip] = collections.deque()
        timestamps = self._request_log[client_ip]
        # Remove entries outside the window
        cutoff = now - RATE_LIMIT_WINDOW
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()
        if len(timestamps) >= RATE_LIMIT_REQUESTS:
            return True
        timestamps.append(now)
        return False

    def request(self, flow: http.HTTPFlow) -> None:
        request_id = generate_request_id()
        flow.metadata["aegis_request_id"] = request_id
        host = flow.request.pretty_host.lower()

        # Rate limiting
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
        if self._is_rate_limited(client_ip):
            block_flow(flow, "rate_limit_exceeded", request_id)
            return

        if self._is_c2_ip(host):
            block_flow(flow, "c2_ip_blocked", request_id)
            return

        if self._is_binary_download(flow) and host not in self.domain_whitelist:
            block_flow(flow, "domain_not_whitelisted", request_id)
            return

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or flow.response.status_code == 403:
            return

        request_id = flow.metadata.get("aegis_request_id", generate_request_id())

        # Response size limit — block oversized responses before further processing
        if flow.response.content and len(flow.response.content) > MAX_RESPONSE_SIZE:
            block_flow(flow, "response_too_large", request_id)
            return

        content_type = flow.response.headers.get("content-type", "")

        if is_script_content(content_type):
            patterns = self.rules.get("dangerous_patterns", [])
            matched = check_dangerous_patterns(flow.response.content, patterns)
            if matched:
                block_flow(flow, "dangerous_script_pattern", request_id, pattern_matched=matched)
                return

        if is_binary_content(content_type):
            verdict = scan_payload(
                flow.response.content, content_type, flow.request.pretty_url, request_id,
            )
            if verdict == Verdict.block:
                block_flow(flow, "scanner_verdict_block", request_id)
                return
            if verdict == Verdict.warn:
                flow.response.headers["X-Aegis-Warning"] = "medium-risk vulnerability detected"
                flow.response.headers["X-Aegis-Request-Id"] = request_id


addons = [AegisAddon()]
