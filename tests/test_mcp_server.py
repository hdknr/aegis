import json
import subprocess
from unittest.mock import patch

import pytest

from aegis.mcp_server import _handle_fetch, _handle_status, _handle_update, list_tools


@pytest.mark.asyncio
async def test_list_tools():
    tools = await list_tools()
    names = [t.name for t in tools]
    assert "aegis_fetch" in names
    assert "aegis_status" in names
    assert "aegis_update" in names


@pytest.mark.asyncio
async def test_fetch_allow():
    mock_result = {
        "url": "https://example.com",
        "status_code": 200,
        "verdict": "allow",
        "reason": None,
        "content_type": "text/html",
        "content": "<html>hello</html>",
    }
    with patch("aegis.mcp_server.fetch_url", return_value=mock_result):
        result = await _handle_fetch({"url": "https://example.com"})

    assert len(result) == 1
    data = json.loads(result[0].text)
    assert data["verdict"] == "allow"


@pytest.mark.asyncio
async def test_fetch_block():
    mock_result = {
        "url": "https://evil.com/malware",
        "status_code": 403,
        "verdict": "block",
        "reason": "dangerous_script_pattern",
        "content_type": "text/x-shellscript",
        "content": None,
    }
    with patch("aegis.mcp_server.fetch_url", return_value=mock_result):
        result = await _handle_fetch({"url": "https://evil.com/malware"})

    data = json.loads(result[0].text)
    assert data["verdict"] == "block"


@pytest.mark.asyncio
async def test_fetch_timeout():
    with patch("aegis.mcp_server.fetch_url", side_effect=subprocess.TimeoutExpired(cmd="curl", timeout=30)):
        result = await _handle_fetch({"url": "https://slow.com"})

    data = json.loads(result[0].text)
    assert data["verdict"] == "block"
    assert "timed out" in data["reason"]


@pytest.mark.asyncio
async def test_status():
    mock_health = {
        "services": {"aegis-scanner": {"status": "healthy"}},
        "environment_ready": True,
    }
    with patch("aegis.mcp_server.get_service_health", return_value=mock_health):
        result = await _handle_status()

    data = json.loads(result[0].text)
    assert data["environment_ready"] is True


@pytest.mark.asyncio
async def test_status_docker_not_found():
    with patch("aegis.mcp_server.get_service_health", side_effect=FileNotFoundError):
        result = await _handle_status()

    data = json.loads(result[0].text)
    assert data["environment_ready"] is False
