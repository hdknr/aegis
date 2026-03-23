# Aegis

Security-first isolated execution environment and scanning gateway for AI agents.

## Project Structure

```
aegis/
├── src/aegis/          # Aegis Gate (CLI + MCP Server) — runs on host
│   ├── cli.py          # Click CLI: aegis fetch/status/up/down/reload/mcp-server
│   ├── mcp_server.py   # MCP Server (stdio transport for Claude Code)
│   ├── executor.py     # Docker Compose exec wrapper
│   └── config.py       # Environment variable config
├── scanner/            # Aegis Blade (Scanner) — runs in Docker
│   ├── main.py         # FastAPI app: GET /health, POST /scan
│   ├── models.py       # Pydantic models (Verdict, ScanResponse, etc.)
│   ├── config.py       # Scanner env config
│   ├── scanners/       # ClamAV + Trivy scan implementations
│   ├── Dockerfile
│   └── entrypoint.sh
├── proxy/              # Aegis Eye (Proxy) — runs in Docker
│   ├── aegis_addon.py  # mitmproxy addon (request + response hooks)
│   ├── content_inspector.py
│   ├── scanner_client.py
│   ├── rules_loader.py
│   ├── utils.py
│   └── Dockerfile
├── worker/             # Aegis Shield (Worker) — runs in Docker
│   ├── Dockerfile
│   └── entrypoint.sh
├── rules/              # Scan rules (mounted into proxy container)
│   ├── rules.yml
│   ├── domain_whitelist.txt
│   └── c2_blocklist.txt
├── docker-compose.yml
├── docs/               # MkDocs documentation
├── tests/              # Unit tests (pytest)
└── scripts/test-e2e.sh # E2E tests
```

## Development

```bash
# Install dependencies
uv sync --group dev

# Run unit tests
make test

# Run E2E tests (requires Docker)
make test-e2e

# Build docs
uv sync --group docs
uv run mkdocs serve
```

## Architecture

4 components coordinated via Docker Compose:

- **Gate** (`src/aegis/`): Host-side CLI + MCP Server. Bridges Claude Code with backend.
- **Shield** (`worker/`): Isolated Docker container for AI agent execution.
- **Eye** (`proxy/`): mitmproxy intercepting proxy. Scans requests/responses.
- **Blade** (`scanner/`): FastAPI + ClamAV + Trivy scanning engine.

Startup order: Blade → Eye → Shield (healthcheck dependencies).

## Key Patterns

- **Fail-closed**: Scanner timeout/error → block (never allow unscanned content)
- **Verdict enum**: `scanner/models.py::Verdict` (allow/block/warn) used across components
- **Content-Type classification**: `proxy/content_inspector.py` — script types get pattern matching, binary types go to scanner, pass-through types skip inspection
- **Rules**: Loaded from `rules/` directory. Proxy supports SIGHUP hot reload.
- **Docker networking**: Worker has no direct internet. All traffic routes through proxy.

## Testing

- Unit tests mock subprocess/socket calls — no Docker required
- E2E tests use `docker compose` — full pipeline verification
- ClamAV tests use mock socket (clamd INSTREAM protocol)
- Proxy tests use mocked mitmproxy flows

## Conventions

- Python managed by `uv` on host, `uv pip install --system` in Docker
- Scanner/proxy each have `requirements.txt` for Docker builds
- Host dependencies in `pyproject.toml` `[project.dependencies]`
- Dev/test dependencies in `[dependency-groups].dev`
- `/simplify` after each PR for code review
