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
  - seccomp=seccomp/worker.json
cap_drop:
  - ALL
cap_add:
  - SETUID   # gosu user switch 用
  - SETGID
```

- `--privileged` は使用しない
- 全ケーパビリティをドロップし、必要最小限のみ追加
- `no-new-privileges` で権限昇格を防止
- seccomp プロファイルで危険な syscall（mount, ptrace, kernel module 等）をブロック

### Filesystem

```yaml
read_only: true
tmpfs:
  - /tmp:size=100M,noexec,nosuid
  - /run:size=10M
  - /home/aegis:size=50M
```

| Mount | Type | Mode | Purpose |
|---|---|---|---|
| `/workspace` | bind | read-write | プロジェクトディレクトリ |
| `/certs` | volume | read-only | mitmproxy CA 証明書 |
| `/tmp` | tmpfs | noexec,nosuid | 一時ファイル（実行不可） |
| `/run` | tmpfs | - | ランタイムファイル |
| `/home/aegis` | tmpfs | - | ユーザーホーム |

ルートファイルシステムは `read_only: true` により読み取り専用。書き込みは tmpfs マウントされた領域のみ許可。

### Process & Resource Limits

```yaml
pids_limit: 128
dns:
  - 127.0.0.11
deploy:
  resources:
    limits:
      memory: 4G
      cpus: "2.0"
```

- `pids_limit: 128` で fork bomb を防止
- DNS は Docker 内部 DNS のみに制限

### Seccomp Profile

`seccomp/worker.json` で以下の syscall をブロック:

| Category | Blocked Syscalls |
|---|---|
| FS マウント | `mount`, `umount2`, `pivot_root`, `sysfs` |
| カーネルモジュール | `init_module`, `finit_module`, `delete_module` |
| デバッグ | `ptrace`, `process_vm_readv`, `process_vm_writev` |
| システム管理 | `reboot`, `swapon`, `swapoff`, `sethostname` |
| カーネルキーリング | `add_key`, `keyctl`, `request_key` |
| eBPF | `bpf`, `perf_event_open` |
| 名前空間操作 | `setns`, `move_mount`, `open_tree` |

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
