import json
import subprocess
from pathlib import Path
from unittest.mock import patch

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


class TestClamavScanner:
    def test_clean_file(self, tmp_path):
        file = tmp_path / "clean.txt"
        file.write_text("hello world")

        mock_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="clean.txt: OK", stderr="")
        with patch("subprocess.run", return_value=mock_result):
            verdict, detail = clamav_scanner.scan(file)

        assert verdict == Verdict.allow
        assert detail.result == "OK"

    def test_infected_file(self, tmp_path):
        file = tmp_path / "evil.bin"
        file.write_bytes(b"\x00" * 100)

        mock_result = subprocess.CompletedProcess(
            args=[], returncode=1,
            stdout="evil.bin: Win.Trojan.Agent-123 FOUND", stderr=""
        )
        with patch("subprocess.run", return_value=mock_result):
            verdict, detail = clamav_scanner.scan(file)

        assert verdict == Verdict.block
        assert detail.result == "INFECTED"
        assert "Win.Trojan.Agent" in detail.threat

    def test_timeout(self, tmp_path):
        file = tmp_path / "slow.bin"
        file.write_bytes(b"\x00")

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="clamdscan", timeout=30)):
            verdict, detail = clamav_scanner.scan(file)

        assert verdict == Verdict.block
        assert detail.result == "TIMEOUT"

    def test_binary_not_found(self, tmp_path):
        file = tmp_path / "test.bin"
        file.write_bytes(b"\x00")

        with patch("subprocess.run", side_effect=FileNotFoundError):
            verdict, detail = clamav_scanner.scan(file)

        assert verdict == Verdict.block
        assert detail.result == "ERROR"

    def test_error_return_code(self, tmp_path):
        file = tmp_path / "test.bin"
        file.write_bytes(b"\x00")

        mock_result = subprocess.CompletedProcess(args=[], returncode=2, stdout="", stderr="ERROR: some error")
        with patch("subprocess.run", return_value=mock_result):
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
