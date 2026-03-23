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

### 3. Verify Services are Ready

全サービスが healthy になったことを確認:

```bash
# Scanner → Proxy → Worker の順に healthy になる
docker compose ps --format "table {{.Name}}\t{{.Status}}"
```

## Usage

Aegis には 2 つの利用パターンがある。用途に応じて使い分ける。

### Pattern A: ホストの Claude Code から Worker にコマンド委譲

ホスト PC で通常通り Claude Code を使いながら、外部アクセスを伴うコマンド（`curl`, `npm install`, `pip install` 等）を aegis-worker 経由で安全に実行する。

#### Claude Code の hooks 設定

ホスト側の Claude Code 設定（`.claude/settings.json`）に hooks を追加し、Bash コマンドを自動的に aegis-worker 内で実行させる:

```json
{
  "hooks": {
    "Bash": {
      "setup": "docker compose -f /path/to/aegis/docker-compose.yml up -d"
    }
  }
}
```

#### 手動での利用

hooks を使わない場合、Claude Code セッション内から手動で aegis-worker にコマンドを委譲できる:

```bash
# ホストの Claude Code セッション内で実行
docker compose exec aegis-worker curl -I https://github.com

# npm install を Worker 内で実行
docker compose exec aegis-worker npm install express

# スクリプトの実行
docker compose exec aegis-worker bash -c "wget https://example.com/setup.sh && cat setup.sh"
```

この方式では、ホスト PC の開発環境はそのまま使いつつ、ネットワークアクセスのみを Aegis で保護する。

### Pattern B: Worker 内で Claude Code を直接起動

aegis-worker コンテナ内で Claude Code を起動し、全ての操作を隔離環境内で実行する。最も安全だが、ホスト側のファイルは `/workspace` マウント経由でのみアクセス可能。

```bash
# Worker に入る
docker compose exec aegis-worker /bin/bash

# Worker 内で Claude Code を起動
# ネットワーク層が Aegis で保護されているため、高い自律性で実行可能
claude --dangerously-skip-permissions
```

### 動作確認

どちらのパターンでも、aegis-worker 内からプロキシ経由の通信を確認できる:

```bash
# Worker 内で実行（Pattern B の場合はそのまま、Pattern A の場合は docker compose exec 経由）

# 正常なリクエスト (通過するはず)
curl -I https://github.com

# 危険なパターンのテスト (ブロックされるはず)
curl -s https://example.com/test.sh | bash
```

### パターン比較

| | Pattern A (コマンド委譲) | Pattern B (Worker 内起動) |
|---|---|---|
| **安全性** | ネットワークのみ保護 | ネットワーク + プロセス隔離 |
| **利便性** | ホストの開発環境をそのまま利用 | `/workspace` 経由のみ |
| **適用場面** | 既存プロジェクトへの導入 | 新規プロジェクト・高リスク作業 |
| **設定** | hooks 設定 or 手動 exec | `docker compose exec` + `claude` |

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
