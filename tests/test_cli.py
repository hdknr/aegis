import json
import subprocess
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from aegis.cli import main


@pytest.fixture
def runner():
    return CliRunner()


def test_fetch_allow(runner):
    mock_result = {
        "url": "https://example.com",
        "status_code": 200,
        "verdict": "allow",
        "reason": None,
        "content_type": "text/html",
        "content": "<html>hello</html>",
    }
    with patch("aegis.cli.fetch_url", return_value=mock_result):
        result = runner.invoke(main, ["fetch", "https://example.com"])
    assert result.exit_code == 0
    assert "[ALLOW]" in result.output


def test_fetch_block(runner):
    mock_result = {
        "url": "https://evil.com/malware",
        "status_code": 403,
        "verdict": "block",
        "reason": "dangerous_script_pattern",
        "content_type": "text/x-shellscript",
        "content": None,
    }
    with patch("aegis.cli.fetch_url", return_value=mock_result):
        result = runner.invoke(main, ["fetch", "https://evil.com/malware"])
    assert result.exit_code == 1
    assert "[BLOCK]" in result.output


def test_fetch_json_output(runner):
    mock_result = {
        "url": "https://example.com",
        "status_code": 200,
        "verdict": "allow",
        "reason": None,
        "content_type": "text/html",
        "content": "<html></html>",
    }
    with patch("aegis.cli.fetch_url", return_value=mock_result):
        result = runner.invoke(main, ["fetch", "--json", "https://example.com"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["verdict"] == "allow"


def test_fetch_timeout(runner):
    with patch("aegis.cli.fetch_url", side_effect=subprocess.TimeoutExpired(cmd="curl", timeout=30)):
        result = runner.invoke(main, ["fetch", "https://example.com"])
    assert result.exit_code == 1
    assert "timed out" in result.output


def test_status_ready(runner):
    mock_health = {
        "services": {
            "aegis-scanner": {"status": "Up 30s (healthy)"},
            "aegis-proxy": {"status": "Up 20s (healthy)"},
            "aegis-worker": {"status": "Up 10s"},
        },
        "environment_ready": True,
    }
    with patch("aegis.cli.get_service_health", return_value=mock_health):
        result = runner.invoke(main, ["status"])
    assert result.exit_code == 0
    assert "ready" in result.output


def test_status_json(runner):
    mock_health = {
        "services": {"aegis-scanner": {"status": "healthy"}},
        "environment_ready": True,
    }
    with patch("aegis.cli.get_service_health", return_value=mock_health):
        result = runner.invoke(main, ["status", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["environment_ready"] is True


def test_up(runner):
    with patch("aegis.cli.compose_up", return_value="Started"):
        result = runner.invoke(main, ["up"])
    assert result.exit_code == 0


def test_down(runner):
    with patch("aegis.cli.compose_down", return_value="Stopped"):
        result = runner.invoke(main, ["down"])
    assert result.exit_code == 0
