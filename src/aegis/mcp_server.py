import asyncio
import json
import subprocess
from functools import partial

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from aegis.executor import exec_in_worker, fetch_url, get_service_health

server = Server("aegis")


@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="aegis_fetch",
            description=(
                "Fetch a URL through Aegis security scanning pipeline. "
                "IMPORTANT behavior rules based on verdict: "
                "verdict 'allow': Safe content. Proceed without asking the user. "
                "verdict 'warn': Potential risk detected. Show the warning details "
                "to the user and ask for confirmation (Y/N) before using the content. "
                "verdict 'block': Threat detected. Show the block reason and scan "
                "details to the user and ask for confirmation (Y/N) before proceeding. "
                "Do NOT use blocked content unless the user explicitly approves."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch"},
                    "method": {"type": "string", "description": "HTTP method", "default": "GET"},
                },
                "required": ["url"],
            },
        ),
        Tool(
            name="aegis_status",
            description="Check the health status of all Aegis services (scanner, proxy, worker).",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="aegis_update",
            description="Update definition databases (ClamAV, Trivy, C2 blocklist).",
            inputSchema={
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["clamav", "trivy", "c2"]},
                        "description": "Which databases to update. Omit to update all.",
                    },
                },
            },
        ),
    ]


async def _run_sync(fn, *args, **kwargs):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, partial(fn, *args, **kwargs))


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "aegis_fetch":
        return await _handle_fetch(arguments)
    elif name == "aegis_status":
        return await _handle_status()
    elif name == "aegis_update":
        return await _handle_update(arguments)
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def _handle_fetch(arguments: dict) -> list[TextContent]:
    url = arguments["url"]
    try:
        result = await _run_sync(fetch_url, url)
    except subprocess.TimeoutExpired:
        return [TextContent(type="text", text=json.dumps({
            "url": url, "verdict": "block", "reason": "request timed out",
        }))]
    except FileNotFoundError:
        return [TextContent(type="text", text=json.dumps({
            "url": url, "verdict": "block",
            "reason": "Docker Compose not found. Is the Aegis environment running?",
        }))]

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def _handle_status() -> list[TextContent]:
    try:
        result = await _run_sync(get_service_health)
    except FileNotFoundError:
        result = {"services": {}, "environment_ready": False}

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


def _update_target(target: str) -> dict:
    try:
        r = exec_in_worker(
            ["curl", "-sf", "-X", "POST", "http://aegis-scanner:8080/update",
             "-H", "Content-Type: application/json",
             "-d", json.dumps({"targets": [target]})],
            timeout=120,
        )
        return {"status": "updated" if r.returncode == 0 else "failed"}
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}


async def _handle_update(arguments: dict) -> list[TextContent]:
    targets = arguments.get("targets", ["clamav", "trivy", "c2"])
    results = {}

    for target in ["clamav", "trivy"]:
        if target in targets:
            results[target] = await _run_sync(_update_target, target)

    if "c2" in targets:
        results["c2_blocklist"] = {"status": "not_implemented"}

    return [TextContent(type="text", text=json.dumps(results, indent=2))]


async def run():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())
