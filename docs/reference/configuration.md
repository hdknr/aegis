# Configuration Reference

全コンポーネントの設定パラメータ一覧。

## Environment Variables

### aegis-worker

| Variable | Default | Description |
|---|---|---|
| `HTTP_PROXY` | `http://aegis-proxy:8080` | HTTP プロキシ URL |
| `HTTPS_PROXY` | `http://aegis-proxy:8080` | HTTPS プロキシ URL |
| `NO_PROXY` | `aegis-scanner,localhost,127.0.0.1` | プロキシを bypass するホスト |
| `NODE_EXTRA_CA_CERTS` | `/certs/mitmproxy-ca-cert.pem` | Node.js 追加 CA 証明書パス |
| `AEGIS_WORKSPACE` | `/workspace` | ワークスペースディレクトリ |

### aegis-proxy

| Variable | Default | Description |
|---|---|---|
| `AEGIS_SCANNER_URL` | `http://aegis-scanner:8080` | Scanner API の URL |
| `AEGIS_RULES_PATH` | `/opt/aegis/rules` | ルールファイルディレクトリ |
| `AEGIS_LOG_LEVEL` | `INFO` | ログレベル (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `AEGIS_FAIL_MODE` | `closed` | Scanner 障害時の動作 (`closed` = ブロック, `open` = 通過) |
| `AEGIS_SCAN_TIMEOUT_MS` | `30000` | Scanner API タイムアウト (ms) |

### aegis-scanner

| Variable | Default | Description |
|---|---|---|
| `AEGIS_SCAN_TIMEOUT` | `30000` | スキャンタイムアウト (ms) |
| `AEGIS_MAX_FILE_SIZE` | `52428800` | 最大スキャンファイルサイズ (bytes, default 50MB) |
| `AEGIS_WORKERS` | `2` | uvicorn worker 数 |
| `CLAMAV_DB_PATH` | `/var/lib/clamav` | ClamAV 定義ファイルパス |
| `FRESHCLAM_INTERVAL` | `21600` | ClamAV DB 更新間隔 (秒, default 6 時間) |

## Rules Files

ルールファイルは `aegis-proxy` の `AEGIS_RULES_PATH` ディレクトリに配置する。

### Directory Structure

```
rules/
├── rules.yml              # Scan rules (patterns, severity)
├── domain_whitelist.txt   # Allowed domains for binary downloads
└── c2_blocklist.txt       # Blocked C2 IP addresses/ranges
```

### rules.yml Schema

```yaml
# Dangerous script patterns to detect in response bodies
dangerous_patterns:
  - name: string          # Rule identifier (unique)
    pattern: string       # Regex pattern
    severity: string      # critical | high | medium | low
    description: string   # Human-readable description

# Content-Type based rules
content_type_rules:
  scan_required:          # Always forward to scanner
    - "application/x-executable"
    - "application/octet-stream"
  pattern_check:          # Check for dangerous patterns
    - "text/x-shellscript"
    - "text/x-python"
  pass_through:           # No inspection needed
    - "text/html"
    - "application/json"
```

### domain_whitelist.txt Format

```text
# One domain per line
# Lines starting with # are comments
# Empty lines are ignored
github.com
registry.npmjs.org
```

### c2_blocklist.txt Format

```text
# CIDR notation
# Lines starting with # are comments
# Empty lines are ignored
198.51.100.0/24
203.0.113.0/24
```

## Docker Volumes

| Volume | Container | Mount Point | Description |
|---|---|---|---|
| `clamav-db` | aegis-scanner | `/var/lib/clamav` | ClamAV 定義ファイル |
| `aegis-certs` | aegis-proxy | `/home/mitmproxy/.mitmproxy` | mitmproxy CA 証明書 |
| `aegis-certs` | aegis-worker | `/certs` (read-only) | CA 証明書参照 |

## Ports

| Port | Service | Protocol | Description |
|---|---|---|---|
| 8080 | aegis-proxy | HTTP | Proxy listen port (internal) |
| 8081 | aegis-proxy | HTTP | mitmweb UI (development only) |
| 8080 | aegis-scanner | HTTP | Scanner API (internal) |
