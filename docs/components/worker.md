# Aegis Shield (Worker)

AI エージェントが動作する隔離実行環境。

## Overview

`aegis-worker` は Docker コンテナとして動作し、AI エージェント（Claude Code）の全操作をホストシステムから隔離する。全ての外部通信は `aegis-proxy` 経由に制限される。

## Base Image

| Item | Value |
|---|---|
| OS | Ubuntu 24.04 LTS |
| Runtime | Node.js 22 LTS |
| User | `aegis` (non-root, UID 1000) |

## Pre-installed Tools

| Tool | Purpose |
|---|---|
| `git` | Version control |
| `curl`, `wget` | HTTP client (proxy 経由) |
| `python3` | Scripting |
| `node`, `npm` | JavaScript runtime |
| `claude` | Claude Code CLI |

## Network Configuration

Worker コンテナは **直接の外部ネットワークアクセスを持たない**。全ての HTTP/HTTPS トラフィックは環境変数でプロキシ経由に強制される。

```bash
HTTP_PROXY=http://aegis-proxy:8080
HTTPS_PROXY=http://aegis-proxy:8080
NO_PROXY=aegis-scanner,localhost,127.0.0.1
```

## Security Constraints

### Container Privileges

```yaml
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
cap_add:
  - NET_RAW  # ping 等の基本ネットワーク診断用
```

- `--privileged` は使用しない
- 全ケーパビリティをドロップし、必要最小限のみ追加
- `no-new-privileges` で権限昇格を防止

### Filesystem

| Mount | Type | Mode | Purpose |
|---|---|---|---|
| `/workspace` | bind | read-write | プロジェクトディレクトリ |
| `/usr/local/share/ca-certificates/aegis.crt` | bind | read-only | mitmproxy CA 証明書 |

### Resource Limits

```yaml
deploy:
  resources:
    limits:
      memory: 4G
      cpus: "2.0"
```

## TLS Configuration

mitmproxy が HTTPS トラフィックをインターセプトするため、mitmproxy の CA 証明書を Worker の信頼ストアに追加する。

```dockerfile
COPY aegis-ca.crt /usr/local/share/ca-certificates/aegis.crt
RUN update-ca-certificates
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/aegis.crt
```

## Dockerfile Outline

```dockerfile
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    curl wget git python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Node.js 22 LTS
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs

# Non-root user
RUN useradd -m -s /bin/bash -u 1000 aegis
USER aegis
WORKDIR /workspace

# Claude Code CLI
RUN npm install -g @anthropic-ai/claude-code

# mitmproxy CA cert (injected at runtime via volume)
# update-ca-certificates runs in entrypoint
```

## Usage

```bash
# Enter the worker container
docker compose exec aegis-worker /bin/bash

# Run Claude Code (proxy protects the network layer)
claude --dangerously-skip-permissions
```
