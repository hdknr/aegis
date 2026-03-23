# Architecture

## System Overview

Aegis は Docker Compose で連携する 3 つのサービスから構成される。

```mermaid
graph TB
    subgraph Host["Host Machine"]
        subgraph DockerNetwork["aegis-net (Docker Bridge Network)"]
            Worker["aegis-worker<br/>Ubuntu + Node.js<br/>Claude Code"]
            Proxy["aegis-proxy<br/>mitmproxy + Python addon"]
            Scanner["aegis-scanner<br/>FastAPI + ClamAV + Trivy"]
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

## Request Lifecycle

AI エージェントが外部リクエストを発行してからレスポンスを受け取るまでの全フロー。

```mermaid
sequenceDiagram
    participant Agent as AI Agent<br/>(aegis-worker)
    participant Proxy as Aegis Eye<br/>(aegis-proxy)
    participant Scanner as Aegis Blade<br/>(aegis-scanner)
    participant Ext as External Server

    Agent->>Proxy: HTTP(S) request via proxy

    Note over Proxy: request() hook
    Proxy->>Proxy: Check domain whitelist
    Proxy->>Proxy: Check C2 IP blocklist

    alt Domain blocked or C2 IP detected
        Proxy-->>Agent: 403 Forbidden + reason
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
                Proxy-->>Agent: 403 Forbidden + scan details
            else verdict = allow or warn
                Proxy-->>Agent: Response (+ warning header if warn)
            end
        else Safe Content-Type
            Proxy-->>Agent: Response (pass-through)
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
    Scanner["aegis-scanner"] -->|healthcheck| Proxy["aegis-proxy"]
    Proxy -->|healthcheck| Worker["aegis-worker"]
```

起動順序: Scanner (最初) → Proxy (Scanner の healthcheck 通過後) → Worker (Proxy の healthcheck 通過後)
