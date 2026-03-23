# Aegis

**Security-first isolated execution environment and scanning gateway for AI agents.**

## Problem

AI エージェント（Claude Code 等）がソフトウェア開発タスクを実行する際、外部リソースへのアクセスやコマンド実行が必要になる。しかし、これらの操作には以下のリスクが伴う:

- 悪意あるパッケージのダウンロード（サプライチェーン攻撃）
- 危険なスクリプトの実行（`curl | bash` パターン）
- 機密情報の外部送信（データ窃取）
- C2 サーバーへの接続（マルウェア通信）

## Solution

Aegis は **統合レイヤー + 3 層の防御** により、AI エージェントの操作を安全に実行する環境を提供する。

### [Aegis Gate](components/gate.md) (MCP Server / CLI)

統合レイヤー。ホスト PC の Claude Code と Aegis バックエンドを接続する。MCP Server として Claude Code のツール（`aegis_fetch`, `aegis_scan` 等）を提供し、外部 URL の取得やコンテンツのスキャンをシームレスに実行する。CLI としても直接利用可能。

### [Aegis Shield](components/worker.md) (aegis-worker)

プロセス隔離層。Docker コンテナ内で AI エージェントを実行し、ホストシステムを保護する。全ての外部通信はプロキシ経由に制限される。

### [Aegis Eye](components/proxy.md) (aegis-proxy)

トラフィック検査層。mitmproxy ベースの HTTP/HTTPS インターセプトプロキシが、全てのリクエスト・レスポンスをリアルタイムで検査し、危険なパターンをブロックする。

### [Aegis Blade](components/scanner.md) (aegis-scanner)

深層スキャン層。ClamAV と Trivy を用いた非同期スキャンエンジンが、ダウンロードされたバイナリやスクリプトのマルウェア・脆弱性を検出する。

## Design Principles

- **Defense in Depth**: 単一の防御層に依存しない多層防御
- **Fail-Closed**: スキャナー障害時はリクエストをブロック（安全側に倒す）
- **Least Privilege**: Worker コンテナの権限を最小限に制限
- **Transparency**: 全てのブロック・警告を構造化ログで記録
