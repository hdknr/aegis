# Architecture

## System Overview

Aegis は Docker Compose で連携する 3 つのサービスから構成される。

```mermaid
graph TB
    subgraph Host["Host Machine"]
        subgraph DockerNetwork["aegis-net (Docker Bridge Network)"]
            Worker["Aegis Shield<br/>(aegis-worker)<br/>Ubuntu + Node.js + Claude Code"]
            Proxy["Aegis Eye<br/>(aegis-proxy)<br/>mitmproxy + Python addon"]
            Scanner["Aegis Blade<br/>(aegis-scanner)<br/>FastAPI + ClamAV + Trivy"]
        end
    end
    Internet["External Internet"]

    Worker -->|"HTTP/HTTPS<br/>(via HTTP_PROXY)"| Proxy
    Proxy -->|"POST /scan<br/>(payload inspection)"| Scanner
    Scanner -->|"verdict:<br/>allow / block / warn"| Proxy
    Proxy -->|"allowed requests only"| Internet
    Internet -->|"response"| Proxy
    Proxy -->|"scanned response"| Worker

    style Worker fill:#4a90d9,color:#fff
    style Proxy fill:#e8a838,color:#fff
    style Scanner fill:#d94a4a,color:#fff
    style Internet fill:#888,color:#fff
```

| Service | Codename | Docker Service | Role |
|---|---|---|---|
| [Aegis Shield](components/worker.md) | Shield | `aegis-worker` | AI エージェントの隔離実行環境（プロセス隔離層） |
| [Aegis Eye](components/proxy.md) | Eye | `aegis-proxy` | HTTP/HTTPS インターセプトプロキシ（トラフィック検査層） |
| [Aegis Blade](components/scanner.md) | Blade | `aegis-scanner` | ClamAV + Trivy スキャンエンジン（深層スキャン層） |

## Request Lifecycle

ユーザーはホスト PC のコンソールで Claude Code を操作する。外部リソースへのアクセスが必要な場合、2 つの利用パターンがある:

- **パターン A**: ホストの Claude Code が aegis-worker にコマンドを委譲する（`docker compose exec` 経由）
- **パターン B**: aegis-worker 内で直接 Claude Code を起動する（`claude --dangerously-skip-permissions`）

いずれの場合も、aegis-worker からの外部通信は全て Aegis Eye (proxy) を経由する。

```mermaid
sequenceDiagram
    participant User as User<br/>(Host PC)
    participant Claude as Claude Code<br/>(Host)
    participant Worker as Aegis Shield<br/>(aegis-worker)
    participant Proxy as Aegis Eye<br/>(aegis-proxy)
    participant Scanner as Aegis Blade<br/>(aegis-scanner)
    participant Ext as External Server

    alt Pattern A: Host Claude Code delegates to Worker
        User->>Claude: Operate via console
        Claude->>Worker: docker compose exec<br/>(curl, npm install, etc.)
    else Pattern B: Claude Code runs inside Worker
        User->>Worker: docker compose exec bash
        Note over Worker: claude --dangerously-skip-permissions
        Worker->>Worker: Claude Code executes command
    end

    Worker->>Proxy: HTTP(S) request via HTTP_PROXY

    Note over Proxy: request() hook
    Proxy->>Proxy: Check domain whitelist
    Proxy->>Proxy: Check C2 IP blocklist

    alt Domain blocked or C2 IP detected
        Proxy-->>Worker: 403 Forbidden + reason
    else Request allowed
        Proxy->>Ext: Forward request
        Ext-->>Proxy: Response

        Note over Proxy: response() hook
        Proxy->>Proxy: Check Content-Type

        alt Script or binary detected
            Proxy->>Scanner: POST /scan (payload)
            Scanner->>Scanner: ClamAV scan
            Scanner->>Scanner: Trivy scan
            Scanner-->>Proxy: verdict + details

            alt verdict = block
                Proxy-->>Worker: 403 Forbidden + scan details
            else verdict = allow or warn
                Proxy-->>Worker: Response (+ warning header if warn)
            end
        else Safe Content-Type
            Proxy-->>Worker: Response (pass-through)
        end
    end
```

## Trust Boundaries

| Boundary | Inside | Outside | Protection |
|---|---|---|---|
| Container isolation | aegis-worker process | Host OS, other containers | Docker namespace/cgroup |
| Network restriction | aegis-net internal traffic | Direct internet access | Worker has no external network |
| Proxy gateway | Inspected/approved traffic | Raw external traffic | mitmproxy + scan rules |
| Scanner verdict | Scanned payloads | Unscanned payloads | ClamAV + Trivy |

## Network Topology

- **aegis-net**: 全コンテナが接続する内部 Docker ブリッジネットワーク
- **Worker**: `aegis-net` のみに接続。直接の外部アクセスなし
- **Proxy**: `aegis-net` + 外部ネットワークに接続。ゲートウェイとして機能
- **Scanner**: `aegis-net` のみに接続。外部アクセス不要（定義ファイル更新時のみ例外）

## Service Dependencies

```mermaid
graph LR
    Scanner["Aegis Blade<br/>(aegis-scanner)"] -->|healthcheck| Proxy["Aegis Eye<br/>(aegis-proxy)"]
    Proxy -->|healthcheck| Worker["Aegis Shield<br/>(aegis-worker)"]
```

起動順序: Blade (最初) → Eye (Blade の healthcheck 通過後) → Shield (Eye の healthcheck 通過後)
