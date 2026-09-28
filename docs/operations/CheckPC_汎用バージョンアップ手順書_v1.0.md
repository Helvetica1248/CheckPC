# CheckPC 汎用バージョンアップ手順書

作成日: 2026-08-01  
対象: CheckPC APT調査パイプラインの将来バージョンアップ  
想定環境: base117相当のLinuxホスト、systemd、外部EnvironmentFile、ローカルvLLM

---

## 1. 目的

本手順書は、CheckPCの現行版を停止可能な状態で保持しながら、新版を別ディレクトリへ展開・検証し、次を満たした場合だけ運用切替するための汎用手順である。

- 配布ZIPを変更せず検証する
- パッケージ内へ秘密設定を置かない
- 現行版と新版のコード・設定を明確に分離する
- 実データ、実LLM、比較gate、release-mode回帰を完了する
- 切替前にロールバック手順を実測する
- 失敗時に現行版へ短時間で復帰できる
- バージョンアップの証跡を再現可能な形で保存する

---

## 2. 標準ディレクトリとシンボリックリンク

### 2.1 バージョン別コード

```text
/opt/llm/checkpc_pipeline_v<OLD>
/opt/llm/checkpc_pipeline_v<NEW>
```

例:

```text
/opt/llm/checkpc_pipeline_v3.69
/opt/llm/checkpc_pipeline_v3.70
```

バージョン別ディレクトリは、展開後に直接上書きしない。同名ZIPや同名ディレクトリの差し替えも行わない。

### 2.2 バージョン別外部設定

```text
/opt/llm/checkpc-pipeline-v<OLD>.env
/opt/llm/checkpc-pipeline-v<NEW>.env
```

秘密値、認証情報、TLS鍵、VT APIキー、proxy認証情報は、必ずパッケージ外のEnvironmentFileに保存する。

### 2.3 運用中バージョンを表す安定リンク

```text
/opt/llm/analysis-current
/opt/llm/checkpc-pipeline-current.env
```

- `analysis-current`: 稼働コードへのリンク
- `checkpc-pipeline-current.env`: 稼働設定へのリンク

バージョンアップ時は、原則としてこの2本だけを切り替える。

### 2.4 データ領域

```text
/srv/checkpc-data/LLM_analysis_result
/srv/checkpc-data/v<NEW>-validation-<timestamp>
```

本番jobsディレクトリを複数のserverプロセスから同時に使用しない。新版検証は専用validationディレクトリを用いる。

---

## 3. 操作上の安全ルール

### 3.1 対話Terminalで`set -e`を使わない

対話Terminalでは、次を実行しない。

```bash
set -euo pipefail
```

`grep`の該当なし、`test`の不成立、`head`によるSIGPIPEだけでシェルが終了するためである。

厳格な終了判定が必要な処理は、専用Runnerスクリプト内だけで次を使う。

```bash
set -euo pipefail
```

### 3.2 確認用コマンドは明示的に判定する

```bash
if grep -q 'pattern' file; then
  echo PASS
else
  echo NOT_FOUND
fi
```

または表示確認だけなら:

```bash
grep 'pattern' file || true
```

`command | head`は`pipefail`環境でSIGPIPEになるため、次を使用する。

```bash
command | sed -n '1,30p'
```

### 3.3 秘密値を表示しない

確認は非空判定だけで行う。

```bash
sudo grep -q '^PIPELINE_AUTH_PBKDF2=.' "$ENV_FILE" &&
echo 'AUTH_HASH=CONFIGURED'
```

次は行わない。

```bash
sudo cat "$ENV_FILE"
env
systemctl show -p Environment
```

---

## 4. バージョンアップ前の必須情報

作業開始前に次を確定する。

```text
OLD_VERSION
NEW_VERSION
OLD_CODE_DIR
NEW_CODE_DIR
OLD_ENV_FILE
NEW_ENV_FILE
INPUT_CORPUS
VALIDATION_ROOT
MODEL_ENDPOINT
SERVICE_NAME
ROLLBACK_VERSION
```

推奨変数例:

```bash
OLD_VERSION='3.69'
NEW_VERSION='3.70'

OLD_CODE="/opt/llm/checkpc_pipeline_v${OLD_VERSION}"
NEW_CODE="/opt/llm/checkpc_pipeline_v${NEW_VERSION}"

OLD_ENV="/opt/llm/checkpc-pipeline-v${OLD_VERSION}.env"
NEW_ENV="/opt/llm/checkpc-pipeline-v${NEW_VERSION}.env"

CURRENT_CODE_LINK='/opt/llm/analysis-current'
CURRENT_ENV_LINK='/opt/llm/checkpc-pipeline-current.env'

SERVICE='checkpc-pipeline.service'
PY='/opt/llm/vllm/venv/bin/python'

VALIDATION_ROOT="/srv/checkpc-data/v${NEW_VERSION//./}-validation-$(date +%Y%m%d_%H%M%S)"
```

---

## 5. 現行環境の事前記録

新版を展開する前に、現在の構成を保存する。

```bash
SNAPSHOT="/srv/checkpc-data/checkpc-upgrade-snapshot-$(date +%Y%m%d_%H%M%S)"
install -d -m 700 "$SNAPSHOT"

sudo systemctl cat checkpc-pipeline.service \
  > "$SNAPSHOT/systemd-cat.txt"

sudo systemctl show checkpc-pipeline.service \
  -p FragmentPath \
  -p DropInPaths \
  -p WorkingDirectory \
  -p ExecStart \
  -p EnvironmentFiles \
  -p MainPID \
  -p ExecMainStartTimestamp \
  > "$SNAPSHOT/systemd-show.txt"

readlink -f /opt/llm/analysis-current \
  > "$SNAPSHOT/analysis-current.txt" 2>&1 || true

readlink -f /opt/llm/checkpc-pipeline-current.env \
  > "$SNAPSHOT/env-current.txt" 2>&1 || true

sudo ss -ltnp \
  > "$SNAPSHOT/listeners.txt"

df -h /opt/llm /srv/checkpc-data \
  > "$SNAPSHOT/disk.txt"
```

稼働版identity:

```bash
cd /opt/llm/analysis-current

"$PY" - <<'PY' \
  > "$SNAPSHOT/runtime-identity.txt"
from runtime_identity import assert_runtime_identity
print(assert_runtime_identity())
PY
```

現在の外部envは秘密値を出さず、メタデータだけ保存する。

```bash
sudo stat -c '%A %U:%G %s %y %n' \
  "$(readlink -f /opt/llm/checkpc-pipeline-current.env)" \
  > "$SNAPSHOT/env-stat.txt"
```

---

## 6. 配布物の受領・凍結

### 6.1 配布一式を保存

配布ZIP、DELIVERY SHA、変更概要、テスト結果、監査結果を同じ受領ディレクトリへ保存する。

```text
checkpc_pipeline_v<NEW>.zip
DELIVERY_SHA256SUMS.txt
v<NEW>_変更概要.md
v<NEW>_TEST_RESULTS.md
監査結果
```

### 6.2 配送SHA確認

```bash
cd <delivery-directory>
sha256sum -c DELIVERY_SHA256SUMS.txt
```

### 6.3 同名差し替え禁止

一度受領したZIPは読み取り専用で保存する。

```bash
chmod 440 checkpc_pipeline_v<NEW>.zip
```

変更が必要な場合は、新しいRC番号または新しい配布識別子で再発行する。

---

## 7. 新版の別ディレクトリ展開

```bash
cd /opt/llm

test ! -e "$NEW_CODE" || {
  echo "既に存在します: $NEW_CODE"
}

sudo unzip -q \
  <delivery-directory>/checkpc_pipeline_v<NEW>.zip

sudo chown -R tksadmin:tksadmin "$NEW_CODE"
```

既存ディレクトリへ上書き展開しない。

---

## 8. 配布完全性確認

```bash
cd "$NEW_CODE"

sha256sum -c SHA256SUMS.txt
```

未記載ファイル確認:

```bash
UNLISTED="$(
  comm -13 \
    <(awk '{sub(/^[^ ]+  /,"");print}' SHA256SUMS.txt | sort) \
    <(find . -type f |
      sed 's|^./||' |
      grep -v '^SHA256SUMS.txt$' |
      sort)
)"

if test -n "$UNLISTED"; then
  echo 'REJECT: SHA未記載ファイル'
  printf '%s\n' "$UNLISTED"
else
  echo 'PASS: SHA記載集合と実ファイル集合が一致'
fi
```

キャッシュ・秘密ファイル確認:

```bash
find . \
  \( -type d \( -name '__pycache__' -o -name '.pytest_cache' -o -name '.git' \) \
  -o -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '.env' -o -name '.env.local' \) \) \
  -print
```

期待: 0件。

verifier:

```bash
"$PY" verify_release_package.py
```

期待:

```text
FAIL=0
```

package integrity機能がある場合:

```bash
"$PY" package_integrity.py .
```

---

## 9. テストポータビリティ確認

将来版では、正式release test前に旧ホスト固定パスがないことを確認する。

```bash
if grep -RInE \
  '/home/claude/|/mnt/user-data/|/tmp/[A-Za-z0-9_-]+/' \
  run_all_tests.py test_*.py
then
  echo 'REJECT: テストにホスト固定パスが残っています'
else
  echo 'PASS: ホスト固定パスなし'
fi
```

実データテストは次の環境変数だけから配置を取得することを標準とする。

```text
CHECKPC_SCRIPTS
CHECKPC_TEST_EXTRACT
CHECKPC_TEST_WORKDIR
CHECKPC_TEST_NESTED_HOST
CHECKPC_TEST_UPLOADS
PIPELINE_JOBS_DIR
```

固定パスが残る配布物は、原則として修正版パッケージを作成し、manifest・SHA・全回帰を再生成する。

---

## 10. 新版EnvironmentFileの作成

### 10.1 現行設定を基点にする

空のテンプレートから秘密値を再入力するのではなく、現行の外部envを複製する。

```bash
sudo cp -a \
  "$(readlink -f "$CURRENT_ENV_LINK")" \
  "$NEW_ENV"

sudo chown root:tksadmin "$NEW_ENV"
sudo chmod 640 "$NEW_ENV"
```

### 10.2 新版固有値だけ変更

```bash
sudoedit "$NEW_ENV"
```

通常変更する項目:

```text
CHECKPC_BUDGET_PROFILE
必要に応じて比較gateディレクトリ
新版専用validation jobs
新版で追加された設定項目
```

維持する項目:

```text
PIPELINE_AUTH_USER
PIPELINE_AUTH_PBKDF2
PIPELINE_BIND_HOST
PIPELINE_PORT / PIPELINE_HTTP_PORT / PIPELINE_HTTPS_PORT
PIPELINE_SSL_CERT
PIPELINE_SSL_KEY
VT_API_KEY
VT_PROXY
CHAT_VLLM_URL
CHAT_MODEL
```

### 10.3 テンプレートとの差分確認

秘密値を表示しない方式で、新版テンプレートに存在するキーがenvに揃っているか検査する。

```bash
TEMPLATE="$NEW_CODE/checkpc-pipeline.env.example"

sudo TEMPLATE="$TEMPLATE" ENV_FILE="$NEW_ENV" python3 - <<'PY'
import os
import re
from pathlib import Path

pat = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)=')

def keys(path):
    result = set()
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        m = pat.match(line.strip())
        if m:
            result.add(m.group(1))
    return result

template = keys(os.environ['TEMPLATE'])
actual = keys(os.environ['ENV_FILE'])

print('missing_keys=', sorted(template - actual))
print('extra_keys=', sorted(actual - template))
PY
```

`missing_keys`がある場合、値を確認して追加する。

---

## 11. systemd標準化

systemdは、バージョン固定パスではなく安定リンクを参照させる。

```bash
sudo systemctl edit checkpc-pipeline.service
```

標準drop-in:

```ini
[Service]
EnvironmentFile=
EnvironmentFile=/opt/llm/checkpc-pipeline-current.env

WorkingDirectory=/opt/llm/analysis-current

ExecStart=
ExecStart=/opt/llm/vllm/venv/bin/python -u /opt/llm/analysis-current/server.py
```

旧`EnvironmentFile`と`ExecStart`は空行でリセットする。

反映:

```bash
sudo systemctl daemon-reload

sudo systemctl show checkpc-pipeline.service \
  -p WorkingDirectory \
  -p ExecStart \
  -p EnvironmentFiles
```

---

## 12. 現行版のまま安定リンク方式へ移行

新版切替前に、安定リンクが現行版を指した状態でサービスが正常動作することを確認する。

```bash
sudo ln -sfnT "$OLD_CODE" "$CURRENT_CODE_LINK"
sudo ln -sfnT "$OLD_ENV" "$CURRENT_ENV_LINK"

sudo systemctl restart "$SERVICE"
```

確認:

```bash
readlink -f "$CURRENT_CODE_LINK"
readlink -f "$CURRENT_ENV_LINK"

sudo systemctl --no-pager --full status "$SERVICE"
```

HTTPS認証:

```bash
curl -sk \
  -o /dev/null \
  -D - \
  https://127.0.0.1/ |
sed -n '1p;/^WWW-Authenticate:/Ip'
```

期待:

```text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic ...
```

---

## 13. 新版の静的・合成回帰

新版サービスへ切り替える前に、CLIで実行する。

```bash
cd "$NEW_CODE"
"$PY" run_all_tests.py \
  --summary-json "$VALIDATION_ROOT/synthetic-test-results.json"
```

この段階では外部実データ依存のSKIPを許容できるが、次を必須とする。

```text
NEW_FAIL=0
KNOWN_FAIL=0
ERROR=0
```

---

## 14. vLLM確認

モデルIDを固定文字列で仮定せず取得する。

```bash
MODEL_ID="$(
  curl --silent --show-error --fail \
    http://127.0.0.1:8000/v1/models |
  "$PY" -c '
import json, sys
rows = json.load(sys.stdin).get("data") or []
if not rows:
    raise SystemExit("model list is empty")
print(rows[0]["id"])
'
)"

printf 'MODEL_ID=%s\n' "$MODEL_ID"
```

---

## 15. 実データsmoke

新版の変更点に直結するsectionを、既存parsed成果物で先行検証する。

必須確認:

```text
selected == evaluated
unevaluated == 0
chunk_errors == 0
semantic binding ACCEPT
release-strict provenance ACCEPT
```

smoke不合格の場合は4modeへ進まない。

---

## 16. 4mode実機解析

標準4mode:

```text
D1 LEAN run1
D1 LEAN run2
D1 FULL run1
D2 LEAN run1
```

各runは別ディレクトリへ保存し、直後に次を実行する。

```bash
"$PY" validate_run_provenance.py \
  "$PARSED" "$ANALYZED" \
  --release-strict \
  --json-out <provenance-result>

"$PY" validate_semantic_binding.py \
  "$PARSED" "$ANALYZED" \
  --json-out <semantic-result>
```

1件でもREJECTなら比較へ進まない。

---

## 17. comparison gate

比較モード:

```text
reproducibility
cross-version
full-lean
depth1-depth2
```

例:

```bash
"$PY" compare_runs.py \
  --mode reproducibility \
  <D1_LEAN_RUN1> <D1_LEAN_RUN2> \
  --output <comparison-dir>/comparison_result_reproducibility.json
```

REVIEW項目がある場合は、証拠を確認し、承認理由を記録する。

```bash
"$PY" comparison_approval.py create \
  <comparison-result.json> \
  --output <approval.json> \
  --approver '<name>' \
  --reason '<具体的な裁定理由>'
```

検証:

```bash
"$PY" comparison_approval.py validate \
  <comparison-result.json> \
  <approval.json>
```

4modeが揃った後:

```bash
"$PY" comparison_release_gate.py \
  <comparison-dir> \
  --json-out <comparison-dir>/comparison_release_gate.json
```

要求:

```text
eligible=true
errors=[]
```

旧版のcomparison gateを新版へ流用しない。

---

## 18. release-mode全回帰

正式切替前に、実データを指定してSKIP=0を確認する。

```bash
CHECKPC_SCRIPTS="$NEW_CODE" \
CHECKPC_TEST_EXTRACT="<release-corpus>" \
CHECKPC_TEST_WORKDIR="<release-corpus>/.test-work" \
CHECKPC_TEST_ENV_LABEL=base117 \
CHECKPC_COMPARISON_GATE_DIR="<new-comparison-dir>" \
PIPELINE_JOBS_DIR="<release-corpus>/.test-jobs" \
CHECKPC_TEST_TIMEOUT_SEC=600 \
CHECKPC_TEST_SHARDS=4 \
"$PY" -u run_all_tests.py \
  --release \
  -v \
  --summary-json <formal-release-results.json>
```

要求:

```text
release_mode=true
environment_label=base117
new_fail=0
known_fail=0
skip=0
error=0
release_blocked=false
formal_release_eligible=true
comparison_gate.eligible=true
```

長時間試験は`nohup` Runnerで実行する。

---

## 19. 切替前チェック

```text
配布SHA PASS
package integrity PASS
release verifier FAIL=0
synthetic NEW_FAIL=0
smoke ACCEPT
4mode provenance/semantic ACCEPT
comparison gate eligible=true
release-mode SKIP=0
ロールバック先のコード・envが存在
現行jobsのバックアップまたは復旧手段あり
```

---

## 20. 新版への切替

```bash
sudo systemctl stop "$SERVICE"

sudo ln -sfnT "$NEW_CODE" "$CURRENT_CODE_LINK"
sudo ln -sfnT "$NEW_ENV" "$CURRENT_ENV_LINK"

sudo systemctl start "$SERVICE"
```

確認:

```bash
readlink -f "$CURRENT_CODE_LINK"
readlink -f "$CURRENT_ENV_LINK"

sudo systemctl show "$SERVICE" \
  -p WorkingDirectory \
  -p ExecStart \
  -p EnvironmentFiles \
  -p MainPID \
  -p ExecMainStartTimestamp
```

identity:

```bash
cd "$CURRENT_CODE_LINK"

"$PY" - <<'PY'
from runtime_identity import assert_runtime_identity
print(assert_runtime_identity())
PY
```

待受:

```bash
sudo ss -ltnp |
grep -E ':(443|8001)\b' || true
```

HTTPS認証:

```bash
curl -sk \
  -o /dev/null \
  -D - \
  https://127.0.0.1/ |
sed -n '1p;/^WWW-Authenticate:/Ip'
```

GUI、チャット、ZIP、PDF、archiveを確認する。

---

## 21. ロールバック

異常時は、コードとenvを必ずセットで戻す。

```bash
sudo systemctl stop "$SERVICE"

sudo ln -sfnT "$OLD_CODE" "$CURRENT_CODE_LINK"
sudo ln -sfnT "$OLD_ENV" "$CURRENT_ENV_LINK"

sudo systemctl start "$SERVICE"
```

確認:

```bash
readlink -f "$CURRENT_CODE_LINK"
readlink -f "$CURRENT_ENV_LINK"

sudo systemctl --no-pager --full status "$SERVICE"
```

新版がjobs schema、index、cacheを変更する場合は、旧版互換性を事前評価し、必要なら切替前のjobs snapshotへ戻す。

---

## 22. 切替後の観察

最低限確認する。

```text
systemd restart loopなし
443 HTTPS認証正常
8001が外部平文待受していない
vLLM接続正常
新規ジョブ作成正常
既存ジョブ参照正常
チャット正常
validation/full ZIP生成正常
PDF正常
VT/proxy設定正常
disk使用量異常なし
journalに秘密値なし
```

---

## 23. 証跡保存

```text
受領ZIP SHA
展開後SHA検証ログ
package integrity
release verifier
synthetic test JSON/log
smoke結果
4mode成果物
provenance/semantic結果
comparison結果・approval・gate
formal release test JSON/log
systemd切替前後
runtime identity
listener確認
GUI確認記録
rollback実測
```

保存先例:

```text
/srv/checkpc-data/v<NEW>-validation-<timestamp>/evidence
```

---

## 24. 禁止事項

- 現行版ディレクトリへの上書き展開
- パッケージ内への`.env`配置
- 旧envを空テンプレートで上書き
- 同一jobsディレクトリへの複数server同時起動
- 旧版comparison gateの流用
- release-mode `SKIP>0`での正式切替
- コードだけ、またはenvだけの片側切替
- package integrity後のパッケージ編集
- 同名ZIPの差し替え
- 秘密値を含むログ共有

---

## 25. 完了条件

```text
runtime identity = 新版
comparison gate eligible=true
formal_release_eligible=true
NEW_FAIL=0
KNOWN_FAIL=0
SKIP=0
ERROR=0
HTTPS認証正常
主要GUI/API正常
ロールバック実測済み
証跡保存済み
```