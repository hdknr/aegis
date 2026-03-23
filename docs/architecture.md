# Architecture

## System Overview

Aegis は Docker Compose で連携する 3 つのバックエンドサービスと、ホスト側の統合レイヤーから構成される。

```mermaid
graph TB
    subgraph Host["Host Machine"]
        ClaudeCode["Claude Code<br/>(Host)"]
        MCP["Aegis Gate<br/>(MCP Server / CLI)"]

        subgraph DockerNetwork["aegis-net (Docker Bridge Network)"]
            Worker["Aegis Shield<br/>(aegis-worker)<br/>Ubuntu + Node.js"]
            Proxy["Aegis Eye<br/>(aegis-proxy)<br/>mitmproxy + Python addon"]
            Scanner["Aegis Blade<br/>(aegis-scanner)<br/>FastAPI + ClamAV + Trivy"]
        end
    end
    Internet["External Internet"]

    ClaudeCode -->|"MCP tools<br/>(aegis_fetch, aegis_scan)"| MCP
    MCP -->|"docker compose exec"| Worker
    Worker -->|"HTTP/HTTPS<br/>(via HTTP_PROXY)"| Proxy
    Proxy -->|"POST /scan<br/>(payload inspection)"| Scanner
    Scanner -->|"verdict:<br/>allow / block / warn"| Proxy
    Proxy -->|"allowed requests only"| Internet
    Internet -->|"response"| Proxy
    Proxy -->|"scanned response"| Worker

    style ClaudeCode fill:#6b4fbb,color:#fff
    style MCP fill:#2ea44f,color:#fff
    style Worker fill:#4a90d9,color:#fff
    style Proxy fill:#e8a838,color:#fff
    style Scanner fill:#d94a4a,color:#fff
    style Internet fill:#888,color:#fff
```

| Service | Codename | Location | Role |
|---|---|---|---|
| [Aegis Gate](components/gate.md) | Gate | Host | MCP Server / CLI — Claude Code とバックエンドの統合レイヤー |
| [Aegis Shield](components/worker.md) | Shield | Docker (`aegis-worker`) | AI エージェントの隔離実行環境（プロセス隔離層） |
| [Aegis Eye](components/proxy.md) | Eye | Docker (`aegis-proxy`) | HTTP/HTTPS インターセプトプロキシ（トラフィック検査層） |
| [Aegis Blade](components/scanner.md) | Blade | Docker (`aegis-scanner`) | ClamAV + Trivy スキャンエンジン（深層スキャン層） |

## Request Lifecycle

ユーザーはホスト PC のコンソールで Claude Code を操作する。外部リソースへのアクセスが必要な場合、以下の利用パターンがある:

- **パターン A (MCP)**: Claude Code が Aegis Gate の MCP ツール（`aegis_fetch` 等）を呼び出す。最も推奨される方式
- **パターン B (CLI)**: ユーザーまたは Claude Code が `aegis` CLI コマンドを直接実行する
- **パターン C (Worker 内起動)**: aegis-worker 内で Claude Code を起動する（`claude --dangerously-skip-permissions`）

いずれの場合も、外部通信は全て Aegis Eye (proxy) → Aegis Blade (scanner) を経由する。

### Pattern A: MCP Server 経由（推奨）

```mermaid
sequenceDiagram
    participant User as User<br/>(Host PC)
    participant Claude as Claude Code<br/>(Host)
    participant Gate as Aegis Gate<br/>(MCP Server)
    participant Worker as Aegis Shield<br/>(aegis-worker)
    participant Proxy as Aegis Eye<br/>(aegis-proxy)
    participant Scanner as Aegis Blade<br/>(aegis-scanner)
    participant Ext as External Server

    User->>Claude: "この URL の内容を確認して"
    Claude->>Gate: aegis_fetch(url)
    Gate->>Worker: docker compose exec curl <url>

    Worker->>Proxy: HTTP(S) request via HTTP_PROXY

    Note over Proxy: request() hook
    Proxy->>Proxy: Check domain whitelist
    Proxy->>Proxy: Check C2 IP blocklist

    alt Domain blocked or C2 IP detected
        Proxy-->>Worker: 403 Forbidden + reason
        Worker-->>Gate: blocked response
        Gate-->>Claude: {verdict: "block", reason: "..."}
    else Request allowed
        Proxy->>Ext: Forward request
        Ext-->>Proxy: Response

        Note over Proxy: response() hook

        alt Script or binary detected
            Proxy->>Scanner: POST /scan (payload)
            Scanner->>Scanner: ClamAV + Trivy scan
            Scanner-->>Proxy: verdict + details

            alt verdict = block
                Proxy-->>Worker: 403 Forbidden
                Worker-->>Gate: blocked response
                Gate-->>Claude: {verdict: "block", details: [...]}
            else verdict = allow or warn
                Proxy-->>Worker: Response
                Worker-->>Gate: content
                Gate-->>Claude: {verdict: "allow/warn", content: "..."}
            end
        else Safe Content-Type
            Proxy-->>Worker: Response (pass-through)
            Worker-->>Gate: content
            Gate-->>Claude: {verdict: "allow", content: "..."}
        end
    end

    Claude->>User: スキャン結果付きで回答
```

### Pattern C: Worker 内で Claude Code を直接起動

```mermaid
sequenceDiagram
    participant User as User<br/>(Host PC)
    participant Worker as Aegis Shield<br/>(aegis-worker)
    participant Proxy as Aegis Eye<br/>(aegis-proxy)
    participant Scanner as Aegis Blade<br/>(aegis-scanner)
    participant Ext as External Server

    User->>Worker: docker compose exec bash
    Note over Worker: claude --dangerously-skip-permissions
    Worker->>Worker: Claude Code executes command

    Worker->>Proxy: HTTP(S) request via HTTP_PROXY
    Proxy->>Ext: Forward (if allowed)
    Ext-->>Proxy: Response
    Proxy->>Scanner: POST /scan (if needed)
    Scanner-->>Proxy: verdict
    Proxy-->>Worker: Response or 403
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
