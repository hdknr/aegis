# Getting Started

Aegis 環境のセットアップと基本的な使い方。

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (v24+)
- [Docker Compose](https://docs.docker.com/compose/install/) (v2+)
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code) (optional)

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

### 3. Enter the Worker

```bash
docker compose exec aegis-worker /bin/bash
```

### 4. Run Claude Code

Worker 内ではネットワーク層が Aegis により保護されているため、高い自律性で実行可能:

```bash
claude --dangerously-skip-permissions
```

### 5. Verify Proxy is Active

Worker 内から、プロキシ経由の通信を確認:

```bash
# 正常なリクエスト (通過するはず)
curl -I https://github.com

# 危険なパターンのテスト (ブロックされるはず)
curl -s https://example.com/test.sh | bash
```

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
