import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scanner.models import Verdict
from scanner.scanners import aggregate_verdict
from scanner.scanners import clamav as clamav_scanner
from scanner.scanners import trivy as trivy_scanner


class TestAggregateVerdict:
    @pytest.mark.parametrize(
        "clamav,trivy,expected",
        [
            (Verdict.allow, Verdict.allow, Verdict.allow),
            (Verdict.allow, Verdict.warn, Verdict.warn),
            (Verdict.allow, Verdict.block, Verdict.block),
            (Verdict.warn, Verdict.allow, Verdict.warn),
            (Verdict.warn, Verdict.warn, Verdict.warn),
            (Verdict.warn, Verdict.block, Verdict.block),
            (Verdict.block, Verdict.allow, Verdict.block),
            (Verdict.block, Verdict.warn, Verdict.block),
            (Verdict.block, Verdict.block, Verdict.block),
        ],
    )
    def test_matrix(self, clamav, trivy, expected):
        assert aggregate_verdict(clamav, trivy) == expected


def _mock_clamd_socket(response: bytes):
    """Create a MagicMock socket returning a clamd response."""
    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sock.recv.side_effect = [response, b""]
    return mock_sock


class TestClamavScanner:
    def test_clean_file(self, tmp_path):
        file = tmp_path / "clean.txt"
        file.write_text("hello world")

        mock_sock = _mock_clamd_socket(b"stream: OK\0")
        with patch("scanner.scanners.clamav.socket.create_connection", return_value=mock_sock):
            verdict, detail = clamav_scanner.scan(file)

        assert verdict == Verdict.allow
        assert detail.result == "OK"

    def test_infected_file(self, tmp_path):
        file = tmp_path / "evil.bin"
        file.write_bytes(b"\x00" * 100)

        mock_sock = _mock_clamd_socket(b"stream: Win.Trojan.Agent-123 FOUND\0")
        with patch("scanner.scanners.clamav.socket.create_connection", return_value=mock_sock):
            verdict, detail = clamav_scanner.scan(file)

        assert verdict == Verdict.block
        assert detail.result == "INFECTED"
        assert "Win.Trojan.Agent" in detail.threat

    def test_timeout(self, tmp_path):
        file = tmp_path / "slow.bin"
        file.write_bytes(b"\x00")

        with patch("scanner.scanners.clamav.socket.create_connection", side_effect=TimeoutError):
            verdict, detail = clamav_scanner.scan(file)

        assert verdict == Verdict.block
        assert detail.result == "TIMEOUT"

    def test_connection_refused(self, tmp_path):
        file = tmp_path / "test.bin"
        file.write_bytes(b"\x00")

        with patch("scanner.scanners.clamav.socket.create_connection", side_effect=ConnectionRefusedError):
            verdict, detail = clamav_scanner.scan(file)

        assert verdict == Verdict.block
        assert detail.result == "ERROR"

    def test_unexpected_response(self, tmp_path):
        file = tmp_path / "test.bin"
        file.write_bytes(b"\x00")

        mock_sock = _mock_clamd_socket(b"stream: UNKNOWN RESPONSE\0")
        with patch("scanner.scanners.clamav.socket.create_connection", return_value=mock_sock):
            verdict, detail = clamav_scanner.scan(file)

        assert verdict == Verdict.block
        assert detail.result == "ERROR"


class TestTrivyScanner:
    def test_no_vulnerabilities(self, tmp_path):
        file = tmp_path / "clean.bin"
        file.write_bytes(b"\x00")

        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout='{"Results": []}', stderr=""
        )
        with patch("subprocess.run", return_value=mock_result):
            verdict, detail = trivy_scanner.scan(file)

        assert verdict == Verdict.allow
        assert detail.result == "NO_VULNERABILITIES"

    def test_critical_vulnerability(self, tmp_path):
        file = tmp_path / "vuln.bin"
        file.write_bytes(b"\x00")

        trivy_output = {
            "Results": [{
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-12345",
                    "Severity": "CRITICAL",
                    "Title": "Remote code execution",
                }]
            }]
        }
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=json.dumps(trivy_output), stderr=""
        )
        with patch("subprocess.run", return_value=mock_result):
            verdict, detail = trivy_scanner.scan(file)

        assert verdict == Verdict.block
        assert detail.result == "CRITICAL"
        assert len(detail.vulnerabilities) == 1
        assert detail.vulnerabilities[0]["id"] == "CVE-2024-12345"

    def test_medium_vulnerability(self, tmp_path):
        file = tmp_path / "med.bin"
        file.write_bytes(b"\x00")

        trivy_output = {
            "Results": [{
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-99999",
                    "Severity": "MEDIUM",
                    "Title": "Info disclosure",
                }]
            }]
        }
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=json.dumps(trivy_output), stderr=""
        )
        with patch("subprocess.run", return_value=mock_result):
            verdict, detail = trivy_scanner.scan(file)

        assert verdict == Verdict.warn
        assert detail.result == "MEDIUM"

    def test_high_vulnerability(self, tmp_path):
        """HIGH severity should report result as 'HIGH', not 'CRITICAL'."""
        file = tmp_path / "high.bin"
        file.write_bytes(b"\x00")

        trivy_output = {
            "Results": [{
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-55555",
                    "Severity": "HIGH",
                    "Title": "Privilege escalation",
                }]
            }]
        }
        mock_result = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=json.dumps(trivy_output), stderr=""
        )
        with patch("subprocess.run", return_value=mock_result):
            verdict, detail = trivy_scanner.scan(file)

        assert verdict == Verdict.block
        assert detail.result == "HIGH"

    def test_timeout(self, tmp_path):
        file = tmp_path / "slow.bin"
        file.write_bytes(b"\x00")

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="trivy", timeout=30)):
            verdict, detail = trivy_scanner.scan(file)

        assert verdict == Verdict.block
        assert detail.result == "TIMEOUT"

    def test_binary_not_found(self, tmp_path):
        file = tmp_path / "test.bin"
        file.write_bytes(b"\x00")

        with patch("subprocess.run", side_effect=FileNotFoundError):
            verdict, detail = trivy_scanner.scan(file)

        assert verdict == Verdict.block
        assert detail.result == "ERROR"

    def test_invalid_json(self, tmp_path):
        file = tmp_path / "test.bin"
        file.write_bytes(b"\x00")

        mock_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="not json", stderr="")
        with patch("subprocess.run", return_value=mock_result):
            verdict, detail = trivy_scanner.scan(file)

        assert verdict == Verdict.block
        assert detail.result == "ERROR"
