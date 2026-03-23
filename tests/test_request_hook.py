import json
from unittest.mock import MagicMock, patch

import pytest

from proxy.aegis_addon import AegisAddon


def _make_flow(url: str = "https://example.com/page.html", host: str = "example.com"):
    flow = MagicMock()
    flow.request.pretty_url = url
    flow.request.pretty_host = host
    flow.request.path = url.split(host, 1)[-1] if host in url else "/"
    flow.request.method = "GET"
    flow.response = None
    flow.metadata = {}
    return flow


@pytest.fixture
def addon(tmp_path):
    whitelist = tmp_path / "domain_whitelist.txt"
    whitelist.write_text("github.com\nregistry.npmjs.org\n")

    blocklist = tmp_path / "c2_blocklist.txt"
    blocklist.write_text("198.51.100.0/24\n")

    rules = tmp_path / "rules.yml"
    rules.write_text("dangerous_patterns: []\n")

    with patch("proxy.aegis_addon.RULES_PATH", tmp_path):
        return AegisAddon()


class TestRequestHookDomainWhitelist:
    def test_html_from_any_domain_allowed(self, addon):
        flow = _make_flow("https://unknown.com/page.html", "unknown.com")
        addon.request(flow)
        assert flow.response is None

    def test_binary_from_whitelisted_domain_allowed(self, addon):
        flow = _make_flow("https://github.com/release.tar.gz", "github.com")
        addon.request(flow)
        assert flow.response is None

    def test_binary_from_unknown_domain_blocked(self, addon):
        flow = _make_flow("https://evil.com/malware.tar.gz", "evil.com")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert body["reason"] == "domain_not_whitelisted"

    def test_exe_from_unknown_domain_blocked(self, addon):
        flow = _make_flow("https://evil.com/setup.exe", "evil.com")
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403


class TestRequestHookC2Blocklist:
    def test_c2_ip_blocked(self, addon):
        flow = _make_flow("https://c2server.com/callback", "c2server.com")
        # Mock DNS resolution to return a C2 IP
        mock_addr = [(None, None, None, None, ("198.51.100.5", 443))]
        with patch("socket.getaddrinfo", return_value=mock_addr):
            addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert body["reason"] == "c2_ip_blocked"

    def test_safe_ip_allowed(self, addon):
        flow = _make_flow("https://safe.com/page.html", "safe.com")
        mock_addr = [(None, None, None, None, ("93.184.216.34", 443))]
        with patch("socket.getaddrinfo", return_value=mock_addr):
            addon.request(flow)
        assert flow.response is None

    def test_dns_failure_allowed(self, addon):
        """DNS failure should not block — fail open for DNS only."""
        flow = _make_flow("https://unknown.com/page", "unknown.com")
        import socket
        with patch("socket.getaddrinfo", side_effect=socket.gaierror):
            addon.request(flow)
        assert flow.response is None


class TestRequestHookMetadata:
    def test_request_id_set(self, addon):
        flow = _make_flow()
        addon.request(flow)
        assert "aegis_request_id" in flow.metadata
        assert flow.metadata["aegis_request_id"].startswith("req_")
