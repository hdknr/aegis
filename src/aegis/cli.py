import json
import subprocess
import sys

import click

from aegis.config import OUTPUT_FORMAT
from aegis.executor import compose_down, compose_up, exec_compose, fetch_url, get_service_health


@click.group()
def main():
    """Aegis - Security gateway for AI agents."""
    pass


@main.command()
@click.argument("url")
@click.option("--json-output", "--json", "json_out", is_flag=True, help="Output as JSON")
@click.option("--timeout", type=int, default=None, help="Request timeout in seconds")
def fetch(url: str, json_out: bool, timeout: int | None):
    """Fetch a URL through Aegis security scanning pipeline."""
    try:
        result = fetch_url(url, timeout=timeout)
    except subprocess.TimeoutExpired:
        click.echo("Error: request timed out", err=True)
        sys.exit(1)
    except FileNotFoundError:
        click.echo("Error: docker compose not found. Is Docker installed?", err=True)
        sys.exit(1)

    if json_out or OUTPUT_FORMAT == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        ct = result.get("content_type", "")
        if result["verdict"] == "block":
            click.echo(f"[BLOCK] {url} — {result.get('reason', 'blocked')}")
        elif result["verdict"] == "warn":
            click.echo(f"[WARN] {url} ({ct}) — {result.get('reason', '')}")
            if result.get("content"):
                click.echo(result["content"])
        else:
            size = len(result.get("content", "") or "")
            click.echo(f"[ALLOW] {url} ({ct}, {size} bytes)")
            if result.get("content"):
                click.echo(result["content"])

    sys.exit(0 if result["verdict"] == "allow" else 1)


@main.command()
@click.option("--json-output", "--json", "json_out", is_flag=True, help="Output as JSON")
def status(json_out: bool):
    """Check Aegis environment health status."""
    try:
        result = get_service_health()
    except FileNotFoundError:
        click.echo("Error: docker compose not found. Is Docker installed?", err=True)
        sys.exit(1)

    if json_out or OUTPUT_FORMAT == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        for name, info in result["services"].items():
            status_str = info.get("status", "unknown")
            click.echo(f"  {name}: {status_str}")
        ready = "ready" if result["environment_ready"] else "not ready"
        click.echo(f"\nEnvironment: {ready}")

    sys.exit(0 if result["environment_ready"] else 1)


@main.command()
def up():
    """Start Aegis environment."""
    click.echo("Starting Aegis environment...")
    output = compose_up()
    click.echo(output)


@main.command()
@click.option("-v", "--volumes", is_flag=True, help="Remove volumes (full cleanup)")
def down(volumes: bool):
    """Stop Aegis environment."""
    click.echo("Stopping Aegis environment...")
    output = compose_down(volumes=volumes)
    click.echo(output)


@main.command()
def reload():
    """Reload proxy rules (hot reload via SIGHUP)."""
    try:
        result = exec_compose("exec", "-T", "aegis-proxy", "kill", "-HUP", "1", timeout=10)
        if result.returncode == 0:
            click.echo("Rules reloaded successfully")
        else:
            click.echo(f"Error: {result.stderr}", err=True)
            sys.exit(1)
    except subprocess.TimeoutExpired:
        click.echo("Error: reload timed out", err=True)
        sys.exit(1)


@main.command("mcp-server")
def mcp_server():
    """Start Aegis MCP Server (stdio transport for Claude Code)."""
    # Lazy import: mcp is a heavy dependency, only load when this command is used
    import asyncio
    from aegis.mcp_server import run
    asyncio.run(run())
