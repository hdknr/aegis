import ipaddress
import logging
import os
import socket
from pathlib import Path

from mitmproxy import http

from proxy.rules_loader import load_c2_blocklist, load_domain_whitelist, load_rules
from proxy.utils import block_flow, generate_request_id

logger = logging.getLogger("aegis-proxy")

RULES_PATH = Path(os.getenv("AEGIS_RULES_PATH", "/opt/aegis/rules"))

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

    def request(self, flow: http.HTTPFlow) -> None:
        request_id = generate_request_id()
        flow.metadata["aegis_request_id"] = request_id
        host = flow.request.pretty_host.lower()

        if self._is_c2_ip(host):
            block_flow(flow, "c2_ip_blocked", request_id)
            return

        if self._is_binary_download(flow) and host not in self.domain_whitelist:
            block_flow(flow, "domain_not_whitelisted", request_id)
            return


addons = [AegisAddon()]
