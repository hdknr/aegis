from unittest.mock import patch, MagicMock

import httpx

from proxy.scanner_client import scan_payload
from scanner.models import Verdict


class TestScanPayload:
    def test_allow_verdict(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"verdict": "allow", "details": []}
        mock_resp.raise_for_status = MagicMock()

        with patch("proxy.scanner_client.httpx.post", return_value=mock_resp):
            result = scan_payload(b"clean", "text/plain", "https://example.com/f", "req_001")

        assert result == Verdict.allow

    def test_block_verdict(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"verdict": "block", "details": []}
        mock_resp.raise_for_status = MagicMock()

        with patch("proxy.scanner_client.httpx.post", return_value=mock_resp):
            result = scan_payload(b"\x00", "application/octet-stream", "https://evil.com/x", "req_002")

        assert result == Verdict.block

    def test_timeout_returns_block(self):
        with patch("proxy.scanner_client.httpx.post", side_effect=httpx.TimeoutException("timeout")):
            result = scan_payload(b"\x00", "application/octet-stream", "https://example.com/x", "req_003")

        assert result == Verdict.block

    def test_connection_error_returns_block(self):
        with patch("proxy.scanner_client.httpx.post", side_effect=httpx.ConnectError("refused")):
            result = scan_payload(b"\x00", "application/octet-stream", "https://example.com/x", "req_004")

        assert result == Verdict.block

    def test_invalid_response_returns_block(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "500", request=MagicMock(), response=MagicMock()
        )

        with patch("proxy.scanner_client.httpx.post", return_value=mock_resp):
            result = scan_payload(b"\x00", "application/octet-stream", "https://example.com/x", "req_005")

        assert result == Verdict.block

    def test_invalid_verdict_defaults_to_block(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"verdict": "unknown_value", "details": []}
        mock_resp.raise_for_status = MagicMock()

        with patch("proxy.scanner_client.httpx.post", return_value=mock_resp):
            result = scan_payload(b"\x00", "application/octet-stream", "https://example.com/x", "req_006")

        assert result == Verdict.block
