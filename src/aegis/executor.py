import json
import subprocess

from aegis.config import COMPOSE_FILE, COMPOSE_PROJECT, TIMEOUT

_SEPARATOR = "\n---AEGIS_CURL_SEP---\n"


def _compose_cmd(*args: str) -> list[str]:
    return ["docker", "compose", "-f", COMPOSE_FILE, "-p", COMPOSE_PROJECT, *args]


def exec_compose(*args: str, timeout: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        _compose_cmd(*args),
        capture_output=True, text=True,
        timeout=timeout or TIMEOUT,
    )


def compose_up() -> str:
    result = subprocess.run(
        _compose_cmd("up", "-d"),
        capture_output=True, text=True, timeout=300,
    )
    return result.stdout + result.stderr


def compose_down(volumes: bool = False) -> str:
    cmd = _compose_cmd("down")
    if volumes:
        cmd.append("-v")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return result.stdout + result.stderr


def compose_ps() -> str:
    result = subprocess.run(
        _compose_cmd("ps", "--format", "table {{.Name}}\t{{.Status}}"),
        capture_output=True, text=True, timeout=10,
    )
    return result.stdout


def exec_in_worker(command: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(
        _compose_cmd("exec", "-T", "aegis-worker", *command),
        capture_output=True,
        timeout=timeout or TIMEOUT,
    )
    return subprocess.CompletedProcess(
        args=result.args,
        returncode=result.returncode,
        stdout=result.stdout.decode("utf-8", errors="replace"),
        stderr=result.stderr.decode("utf-8", errors="replace"),
    )


def fetch_url(url: str, timeout: int | None = None) -> dict:
    """Fetch a URL through aegis-worker and return structured result."""
    # Use a unique separator to avoid ambiguity with body content
    result = exec_in_worker(
        ["curl", "-sL",
         "-w", f"{_SEPARATOR}%{{http_code}}{_SEPARATOR}%{{content_type}}",
         "-D", "/dev/stderr", "-o", "-", url],
        timeout=timeout,
    )

    parts = result.stdout.rsplit(_SEPARATOR.strip(), 2)
    if len(parts) >= 3:
        body = parts[0].rstrip("\n")
        status_code = int(parts[1].strip()) if parts[1].strip().isdigit() else 0
        content_type = parts[2].strip()
    else:
        body = result.stdout
        status_code = 0
        content_type = ""

    headers = result.stderr
    verdict = "allow"
    reason = None
    if status_code == 403 and "aegis" in headers.lower():
        verdict = "block"
        try:
            reason_data = json.loads(body)
            reason = reason_data.get("reason", "blocked by proxy")
        except (json.JSONDecodeError, ValueError):
            reason = "blocked by proxy"
        body = None

    if "X-Aegis-Warning" in headers:
        verdict = "warn"
        reason = "medium-risk vulnerability detected"

    return {
        "url": url,
        "status_code": status_code,
        "verdict": verdict,
        "reason": reason,
        "content_type": content_type,
        "content": body if verdict != "block" else None,
    }


def get_service_health() -> dict:
    """Get health status of all aegis services."""
    ps_output = compose_ps()
    services = {}
    for line in ps_output.strip().splitlines()[1:]:  # skip header
        parts = line.split(None, 1)
        if len(parts) == 2:
            name, status = parts
            services[name] = {"status": status}

    try:
        result = exec_in_worker(
            ["curl", "-sf", "http://aegis-scanner:8080/health"],
            timeout=5,
        )
        if result.returncode == 0:
            scanner_health = json.loads(result.stdout)
            services["aegis-scanner"] = scanner_health
    except Exception:
        pass

    return {
        "services": services,
        "environment_ready": bool(services) and all(
            "healthy" in str(s.get("status", "")).lower()
            or s.get("status") == "healthy"
            for s in services.values()
        ),
    }
