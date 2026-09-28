# J-CRAT CheckPC 解析パイプライン 設計書 v3.71-rc16

**最終更新: 2026-08-24**

## 0. v3.71-rc16の位置付け

v3.70 rev14-formalの解析仕様を基準とし、**v3.71のThreat Intelligence再設計とrc15までの検索・timeline・prevalence・hostname coverage・VT IOC binding境界を維持しつつ、rc15独立監査で残ったVT authorization P0 2系統だけを限定修正した候補版**である。
parser、analyze、correlate、Depth1/2、comparison、formal provenance、source ID algorithm、v370 budgetは変更しない。

v3.70までのチャットは多数のsection/toolから適切なものをLLM自身に選ばせていた。v3.71では公開toolを`investigate_local`と明示外部照会用`vt_ioc_lookup`へ集約し、案件scope、raw/analyzed/correlation選択、mixed-version normalizing、distinct-host prevalence、coverage会計をPython側の責務へ移す。

raw directory等の巨大証拠は、既存SQLite indexを優先し、旧jobで必要な場合だけbounded streaming fallbackを使う。案件全台の巨大directoryを初回chatで同期index化しない。Evidence-derived textはsystem instructionへ直接埋め込まず、非信頼tool result境界を維持する。

`RELEASE_STATUS=validation-pending`であり、この版のfocused regressionは正式昇格を意味しない。base117実LLM・旧案件全数・formal release-modeは後続受入工程で確認する。



### rc16 fail-closed directive boundary / Japanese action terminal

- English external authorizationではbare commaを肯定directive境界として扱わない。comma経由は`, and` / `, then`等の明示的affirmative coordinationだけを許可する。
- `do not, under any circumstances, check ...` / `never, ever, check ...`等の同一否定directive内部のcommaからpositive lookupを開始しない。
- 日本語external actionはaction tokenの部分matchだけではauthorizeせず、action後がdirective終端または安全に認識できる次local/external directiveの場合だけ成立する。
- `確認するのはやめて` / `検索するのはやめて` / `調べてほしくない`等はactionの見かけ上のpositive部分をcaptureしてもfail-closed。
- IPv4の`.`をdirective終端と誤認しない専用Japanese suffix inspectionを使用し、external→localの既存mixed routingを維持する。
- production変更は`chat_tools.py`に限定し、Evidence Index、hostname、Directory/timeline、prevalence、formal analysis pipelineは変更しない。

### rc15 English directive-bound affirmative authorization

- 英語external authorizationはpositive-looking lookup substringの文中部分一致だけでは成立させない。
- 外部lookup matchがdirective境界から開始するか、明示的な肯定coordination (`while` / `and` / `then` / comma coordination) の直後から開始する場合だけauthorization候補とする。
- `no need to` / `there is no need to` / `not necessary to` / `refrain from` / `skip` 等の任意前置文脈は、個別denylist語彙に依存せずfail-closedで拒否する。
- 既存のmatch-local negative suffix判定は追加防御として維持するが、English prefix denylistをsecurity truth sourceにはしない。
- `check A locally while checking B with VirusTotal` / `... and check B with VirusTotal` 等の既存mixed routingはBだけをauthorizeする。
- multi-IOC external operand、same-directive local/context isolation、`foo-and-bar.com`、日本語authorization、VT disabled pre-check/actual groundingのshared authorized setはrc14仕様を維持する。
- production変更は`chat_tools.py`に限定し、Evidence Index、hostname、Directory/timeline、prevalence、formal analysis pipelineは変更しない。

### rc14 directive-local negation / multi-IOC binding

- external lookup grammarがIOCへ直接bindingしていても、その同じdirectiveが明示否定されていればauthorizationを成立させない。
- 日本語は`確認しなくていい/よい`、`確認不要/は不要`、`確認しない`等のaction直後の否定scopeをfail-closedで拒否する。
- 英語は`avoid`、`without`、`rather than`、`instead of`、既存`do not/don't/never`等が同一directiveの外部lookup actionへscopeする場合を拒否する。
- 否定scopeはmatch局所・directive境界内だけで評価し、別の完結したdirectiveの肯定external requestをmessage-wide否定で潰さない。
- `8.8.8.8と1.1.1.1をVirusTotalで調べて`、`check 8.8.8.8 and 1.1.1.1 with VirusTotal`等、external grammarのoperandとして直接bindingされたIOCリストは複数authorizeできる。
- multi-IOC list captureは外部lookup operandそのものに限定し、同一文のlocal/context/comparison IOCをco-occurrenceだけでauthorizeしない。
- English `and`は空白境界を要求し、`foo-and-bar.com`等の有効FQDNをlist splitterとして破壊しない。
- VT disabled pre-checkとactual groundingは従来どおり同じ`authorized_external_iocs`集合をtruth sourceとする。Evidence Index、hostname、Directory/timeline、prevalence、formal analysis pipelineはrc13から変更しない。

### rc13 grammar-captured IOC external authorization

- external authorizationはdirective/clause内のIOC全件を承認せず、明示肯定external lookup grammarが直接captureしたIOC operandだけを`authorized_external_iocs`へ入れる。
- `8.8.8.8はローカルで調べて1.1.1.1をVirusTotalで調べて`、逆順、`そして`、英語`while`、比較contextでも`1.1.1.1`だけをauthorizeする。
- local/context IOC、比較対象、同一文中の別IOCはco-occurrenceだけでは外部送信権限を得ない。binding不能・曖昧な表現はfail-closedとする。
- directive splitterは外部送信authorizationのtruth sourceとして使用しないため、`foo-and-bar.com`等の有効FQDNを`and`で破壊しない。
- VT disabled pre-checkと`_vt_ioc_is_grounded()`は同じIOC-specific authorized setを使用する。
- hostname coverage、Evidence Index、Directory/timeline、prevalence、same-folder、public 2-tool面、formal analysis pipelineはrc12から変更しない。

### rc12 IOC-specific external-TI authorization

- external authorizationのtruth sourceをmessage-wide booleanから`authorized_external_iocs`集合へ変更する。current analyst turnをbounded directiveへ分割し、明示的に外部TI lookupを肯定したdirective内のVT送信可能IOCだけを集合へ入れる。
- `8.8.8.8はローカルで、1.1.1.1をVirusTotalで調べて`では`1.1.1.1`だけを外部送信許可する。Qwenが`8.8.8.8`の`vt_ioc_lookup`を誤生成しても送信前に拒否する。
- `VTで8.8.8.8を確認する必要はない`、`検索してはいけない`、`照会するつもりはない`、`don't check ... with VirusTotal`、`do not look up ... on VT`等はdirective単位でfail-closedにする。
- positive grammarは意図的に狭くし、`...をVirusTotalで調べて`、`VTで照会して`、`VirusTotalに...問い合わせて`、`check ... with VirusTotal`等の明示要求だけを許可する。曖昧な自然言語は外部送信しない。
- VT disabled pre-checkと`_vt_ioc_is_grounded()`は同じ`authorized_external_iocs`集合を利用する。pre-checkとactual transmissionでauthorization semanticsを二重実装しない。
- hostname coverage、Evidence Index、Directory/timeline、prevalence、same-folder、public 2-tool面、formal analysis pipelineはrc11から変更しない。

### rc11 external-TI positive-allowlist gate

- 外部送信許可はnegation denylist依存ではなくpositive allowlistとする。`VT/VirusTotal/外部TI`等のmarkerが、`で/に/を使って`等を介して`調べる/照会/確認/問い合わせ`等の肯定lookup actionへ同一表現内で結合する場合だけexternal intentを成立させる。
- `VTではなく` / `VTじゃなく` / `VT以外で` / `do not use VT` / `don't use VT`等はfail-closed。`VirusTotalとは何？ 8.8.8.8をローカルで調べて`、`VTについて説明して。8.8.8.8はローカルで確認して`のような一般言及＋別local actionもexternal intentにしない。
- positive controlとして`8.8.8.8をVirusTotalで調べて`、`8.8.8.8をVTで照会して`、`VirusTotalに8.8.8.8を問い合わせて`、`check ... with VirusTotal`等は許可する。
- VT disabled pre-checkと`_vt_ioc_is_grounded()`は同一predicateを使用し、その後さらにcurrent-turn exact IOC groundingを要求する。LLMが誤って`vt_ioc_lookup`を生成してもpredicate不成立なら`secure_vt_lookup`へ到達しない。
- hostname coverage、Evidence Index、Directory/timeline、prevalence、same-folder、public 2-tool面、formal analysis pipelineはrc10から変更しない。

### rc10 security-boundary fixes

- external-TI lookupの肯定/否定判定を共通predicateへ一本化し、VT toolが公開されている場合でも明示否定されたcurrent turnからの`vt_ioc_lookup`を外部送信前に拒否する。
- exact IOC groundingは従来どおりcurrent analyst message限定。local evidenceや過去turnは外部送信権限を付与しない。
- exact hostname not-foundでは`correlation_searchable_host_count`と`hostname_searchable_host_count`を分離し、blank/`UNKNOWN` hostnameをabsence proofの分母へ含めない。
- authoritative hostname not-foundは`hostname_searchable_host_count == scope_host_count`かつscope非truncatedの場合だけ。
- public tool面、same-folder boundary、Evidence Index schema/normalizer、Directory/timeline、formal analysis pipelineは変更しない。

### rc9 final chat-boundary fixes

- `search`はgrounded primary queryを維持しつつ、非Directory・非explicit-literalのfree-textだけにbounded identifier token fallbackを許可する。例:`ajrouter service`→`ajrouter`。generic tokenや明示filename/path/hash/IPは広げない。
- `timeline`で具体file/pathを指定した場合、current-host raw Directoryの`date`を`timestamp_kind=filesystem_metadata`として返せる。これは実行時刻・感染時刻・因果を意味しない。other-host coverageを捏造しない。
- 明示hostname存在確認はhost-level correlation metadataだけで決定し、完全coverage時の0 matchだけをauthoritative not-foundとする。不完全coverageでは不存在を断定しない。
- explicit VirusTotal/外部TI lookup requestでVT toolがpolicy/kill-switchにより非公開の場合、LLM/tool dispatch前に「外部TI無効・外部通信なし」を決定論的に返す。`VTを使わず`等の明示否定はこのguardへ入れない。
- shared/high-signal entityの`host_count`はcommonality/prevalenceであり、件数だけから悪性・感染・campaign impact・因果を断定しない。
- public tool面、Evidence Index schema/normalizer、case exact-folder boundary、VT許可時のcurrent-turn exact IOC grounding、formal analysis pipelineは変更しない。

### rc4 correlation summary fast path

- `action=summary`はhost-level `correlation_*.json`を中心とするfast pathとし、cold状態でも`chat_evidence_v1.sqlite`を構築しない。
- correlationのpipeline/schema pairを検証し、存在するanalyzed/parsed artifactのmeta pairと不一致ならfail-closedする。大型analyzed/parsed本文やparsed SHA計算はsummaryでは行わない。
- `correlation_searchable_host_count / correlation_coverage_complete`をsummary専用coverageとして返す。
- coverage不完全時は`observed_high_or_above_host_count`等だけを返し、案件全体の`high_or_above_host_count`、確定distribution、共有/希少結論は`null`とする。
- search/timelineは従来どおりnormalized chat Evidence Indexを使用し、rc3のbounded truncation / actual SHA / schema / Directory coverage安全境界を維持する。
- Evidence Index schema/normalizer自体はrc3から不変のため`NORMALIZER_VERSION=v371-rc3`を意図的に維持し、rc4化だけを理由とする全host cache再buildは行わない。
- base117 rc3実測ではcold 12秒で8/76 host、180秒上限で76/76 cache生成に101秒を要したが、correlation自体は76/76でHIGH=43、MEDIUM=33を取得できた。rc4はtimeout延長ではなく責務分離で対処する。

### rc3 Evidence Pivotの追加安全条件

- `folder` / `status`はscope/control metadataでありsearchable evidenceへ入れない。
- supported schemaの`parsed.sections`にあるstructured list/dictをstreamingでcore index化する。巨大`directory`は別経路のまま。
- parsed structured indexはtrusted/computed SHA-256とschema pairへ結合し、unknown/mismatchはfail-closed。
- Directory系queryのprevalenceはDirectory rawを完全検索できたscopeだけで算出し、coverage不完全時は`prevalence=null`。
- `case_host_count`は実案件母集団、`scope_host_count`はfollow-up subsetを表し、縮約時も混同しない。
- legacy Directory streamingとcore index buildはabsolute deadlineでboundedにする。

## 1. 概要

CheckPC（Windows 初動調査バッチ）が生成する CAB/TXT 出力を自動解析し、
Markdown レポートを生成するローカル LLM パイプライン。

J-CRAT 業務での使用を前提とし、**取りこぼし防止を最優先**とした設計。

---

## 2. 本番環境（base117）

```
機材     : Dell Precision
GPU      : RTX A4500 × 2（各 20GB VRAM / 合計 40GB）
LLM      : Qwen2.5-Coder-32B-Instruct AWQ（v3.51で本採用。served name は
           互換維持のため qwen25-coder-32b-q3 のまま）
推論基盤 : vLLM（Tensor Parallel mode）/ port 8000
設定     : max_model_len=16384、directory max_tokens=2048
           tool-parser: qwen2_5_coder プラグイン（start_vllm.sh 参照）
実測速度 : ~17 tok/sec / directory 1チャンク平均 142〜173s（CW=3時）
           ※ CW=5 は preemption で 249〜483s と逆効果。CW=3 が現行最適値
```

---

## 3. スクリプト構成

```
/opt/llm/analysis/
├── run_analysis.py      # メインラッパー（単体・バッチ両対応）
├── parse_checkpc.py     # Step3: CheckPC テキスト → 構造化 JSON
├── analyze_section.py   # Step4: セクション別 LLM 解析
├── section_prompts.py   # プロンプト・Level1 フィルタ定義
├── correlate.py         # Step5: 横断相関 LLM 解析
├── report_gen.py        # Step6: Markdown レポート生成
├── defender_dir_report.py # 16-D: Defender検知ログ集約＋不審フォルダDirectory抽出（v3.57新規）
├── vt_post.py           # Step7: VT スコア補正（オプション）
├── compare_runs.py      # rc21正式比較ゲート（run dir/full archive入力）
├── comparison_provenance.py # 段階集合・fingerprint・保存則
├── comparison_approval.py   # REVIEW承認をresult SHAへ結合
├── comparison_release_gate.py # 4modeの正式昇格判定
├── context_template.yaml # --context-file テンプレート
└── test_pipeline.py     # 基幹回帰テスト
```

---

## 4. 処理フロー

```
[入力] CheckPC CAB / Base64 CAB (.txt) / CheckPC テキスト (.txt)
         ↓
[Step1] CAB デコード・展開（decode_cab）
         ファイル内容で種別判定（先頭バイト "CheckPC_" or "-----BEGIN"）
         ↓
[Step2] AppCompatCache パース（run_shimcache / ShimCacheParser.py）
         ↓
[Step3] CheckPC テキスト → 構造化 JSON（parse_checkpc.parse()）
         → parsed_{HOSTNAME}_{STAMP}.json
         ↓
[Step4] セクション別 LLM 解析（analyze_section.analyze()）
         section_workers=3 で並列実行
         → analyzed_{HOSTNAME}_{STAMP}.json
         ↓
[Step5] 横断相関 LLM 解析（correlate.correlate()）
         感染嫌疑 HIGH/MEDIUM/LOW/NONE を判定
         → correlation_{HOSTNAME}_{STAMP}.json
         ↓
[Step6] Markdown レポート生成（report_gen.generate_report()）
         標準版・全件版・raw_directory.md を出力
         ↓
[Step7] VT スコア補正（vt_post.vt_enrich() / --vt-key 指定時のみ）
         → analyzed/correlation の _vt 版を追加出力
```

---


## 4-B. LLM 呼び出しのチャンク自動リトライ（P1 / v3.59）

LLM 解析はセクションごとにエントリをチャンク分割して呼び出す
（analyze_section.py call_llm_chunked）。チャンク応答が失敗した場合、
v3.58 までは部分救出＋⚠可視化のみで再試行しなかった。v3.59 で自動リトライを追加。

- 対象: error（接続エラー等）/ parse_error（全滅）/ partial_parse（未評価残あり）
- 方法: 失敗分を半分割して各1回だけ再送する。切断は max_tokens 超過が主因
  （TR-1 で判明済み）のため、件数半減で出力トークンもほぼ半減し高確率で回復する。
- partial_parse では救出済みエントリの source_index を除いた「未評価分のみ」を
  再送（二重評価防止）。source_index が1件でも欠ける場合は安全側で全件再送し、
  identifier（v3.58 の元データ強制上書き済み）で重複排除する。
- 完全回復時は⚠を出さない。監査痕跡は analyzed_*.json の _chunk_timings に
  retry=true として残る。再試行後も未評価が残る場合は従来同様
  「partial_parse: 未評価 = n_entries - n_salvaged」の規約で⚠ MEDIUM 可視化
  （黙って捨てない、からの後退なし。診断に retry_attempted=true が付く）。
- 環境変数: CHECKPC_CHUNK_RETRY=0 で無効（従来動作）。既定 1。
- 処理時間: 正常時ゼロ。失敗チャンク分のみ追加呼び出し（最大2回/チャンク）。
- 回帰テスト: test_chunk_retry_dirsig.py P1-R1〜R6

## 4-C. LEAN出力モード（P3 / v3.62）

LLM出力の72%が元データの書き写し（identifier 41% + iocs 31%、HOST-REF-08実測）
であることに基づき、出力を判定価値（score/reason/mitre/decoded）に絞るモード。
CHECKPC_LEAN_OUTPUT=1 で有効（既定=0/従来動作。A/B合格後にデフォルトON予定）。

- プロンプト: get_prompt(section, depth, lean=True) が展開済み OUTPUT_FORMAT を
  LEAN版へ置換（section_prompts._lean_output_format）。identifier は先頭15文字の
  監査用ヒント、CLEAN は {"source_index","score"} の2フィールドのみ、
  LEAN_IOCS_SECTIONS（構造化12セクション）は iocs 出力なし。LLMへの入力
  （entries_to_text）は一切変更しない。
- カバレッジ検証（_call_chunk_lean）: 返却された source_index の集合と 0〜N-1 を
  突合。無効（範囲外/null/重複）の応答は不採用（誤帰属の構造的防止）、欠落 index
  の元エントリのみを半分割で再送（最大 CHUNK_RETRY 回）。残れば partial_parse
  規約＋lean_coverage フラグで⚠可視化。「source_index を信用する」のではなく
  「不完全なら必ず検出する」設計。実測の LLM 出力 source_index 有効率は 99.5%
  （370/372・v3.61実行）。なお15文字ヒントは同一セクション内の先頭15文字衝突率が
  88%のため照合には使用せず、⚠時の監査表示のみに用いる。
- 決定論付与（_apply_identifier_overwrite 内）: identifier（v3.58）・datetime
  （v3.60）に加え、LEAN時は iocs を _canonical_iocs() で元データから付与。
  CLEAN の欠損フィールドも補完し下流（report/correlate/vt_post/chat）互換を維持。
- A/B受け入れ条件（compare_analyzed.py で判定）: ①HIGH集合の完全一致（必須）
  ②MEDIUM差分の目視レビュー ③⚠/リトライ健全性 ④chunk_timings短縮の確認。
  前提として temperature=0.0（v3.63）。t>0 では同一入力でも判定が揺れるため
  A/B比較が成立しない（初回A/Bで判明）。
- LEAN v2（v3.63）→ v3（v3.64）: v2 で LOW compact＋判定注意を明記したが
  第2回A/B（t=0）でも LOW→CLEAN シフトが残存（LOW 115→70 / CLEAN 174→237）。
  v3 で CLEAN も3フィールド（reason≤20字）とし出力コスト勾配を解消。
  受信側は旧2フィールドも許容。v3 で分布が正常化しなければ LEAN 不採用
  （FULL維持）と判断する（打ち切り条件）。
- A/B実測記録: 第1回（v1・t=0.1）-26.8%・HIGH不一致で不採用。
  第2回（v2・t=0）-52.9%・分布シフトで不採用。
  第3回（v3・t=0）-43.3%（基準③合格）だが分布シフト MEDIUM-15%/LOW-20%/
  CLEAN+24% が基準②(±10%)を超過し、事前合意の打ち切り条件を発動。
- **最終判定（v3.66 / 2026-07-17）: LEAN 採用・既定ON。**
  追加裁定（HOST-REF-11感染機・HOST-REF-02クリーン機）を含む3ホスト計154件の
  エントリ裁定で実害級の可視性喪失ゼロを確認。lean は run→analyze→
  call_llm_chunked の引数として伝播し（並行ジョブ安全）、GUI からジョブ単位で
  LEAN/FULL を切替可能（今後の他ホスト検証用）。CHECKPC_LEAN_OUTPUT=0 で
  全体をFULLへ復帰可能。残存していた劣化型「reason-score矛盾」は提案10の
  矛盾フロアで決定論封鎖した。
- 判定改訂（v3.65）: エントリ単位裁定により第3回A/Bの変化72件の88%が
  FULL側過剰判定の是正、真の劣化は confabulation 1件と判明。「分布±10%」
  基準は「FULL=正解」の誤前提を含むため廃止し、compare_analyzed.py の
  エントリ単位裁定（自動不合格条件は HIGH→LOW/CLEAN 遷移のみ）へ改訂。
  confabulation は可視性フロア（dns_cache/netstat待受のCLEAN禁止）で決定論的に
  封鎖済み。**採否は HOST-REF-11（感染機）＋ HOST-REF-02（クリーン機）の
  追加裁定で最終判断する（提案9・実施待ち）。**
- 回帰テスト: test_p3_lean_output.py L1〜L8（56件）

## 5. 対応入力形式

| 形式 | 判別方法 | 備考 |
|---|---|---|
| CheckPC テキスト (.txt) | 先頭バイトが `CheckPC_` | CheckPC バッチの直接出力 |
| Base64 CAB (.txt) | 先頭が `-----BEGIN` または上記以外の `.txt` | PEM ラップ含む |
| CAB ファイル (.cab) | 拡張子 `.cab` | cabextract で展開 |

**注意:** ファイル名が `CHECKPC_*.txt` であっても、内容が Base64 CAB の場合は
正しくデコードされる（ファイル名ではなく内容で判別）。

---

## 6. 解析セクション一覧

rc3ではさらに以下を必須とする。

- parsed structured scannerは`sections`と`event_logs`の双方を同一のfail-closedルールで走査する。`directory`は別経路のままとする。
- 1 recordのscalar数/長さ/depthによるbounded truncationをindex metadataへ記録し、発生hostをcoverage-complete/prevalence分母へ含めない。
- analyzed / correlation / parsedのpipeline/schema pairを個別に検証し、存在するformal artifact間の不一致は`artifact_schema_mismatch`で拒否する。
- parsed cache identityはclaimed SHAだけでなく実parsed fileのstreaming SHA-256へ結合し、不一致は`source_artifact_sha_mismatch`で拒否する。
- analyzed/correlation JSONにはread前size capとdeadline-aware bounded loadを適用する。
- 200 host capでscopeを切った場合は`scope_truncated=true` / `case_coverage_complete=false`を返し、案件全数検索済みと表現しない。

### 6-1. LLM 解析セクション（depth=1 の設定値）

| セクション | 用途 | depth=1 chunk | depth=1 max_tokens | 評価方式 |
|---|---|---:|---:|---|
| persistence_reg | 永続化レジストリ | 8 | 1024 | LLM |
| association_exe | EXE関連付け | 8 | 1024 | LLM |
| uac_bypass | UAC bypass関連 | 8 | 1024 | LLM |
| active_setup | Active Setup | 8 | 1024 | LLM |
| com_persistence | COM永続化 | 8 | 1024 | LLM |
| wmi | WMI Consumer | 6 | 1024 | LLM（Filter/Binding未収集注記） |
| task_106 | タスク登録 | 6 | 1024 | LLM |
| task_140 | タスク更新 | 6 | 1024 | LLM |
| recent_behavior | RunMRU/TypedURLs等 | 10 | 1024 | LLM |
| startup_folder | スタートアップ | 8 | 1024 | LLM |
| task_scheduler | タスクスケジューラ | 8 | 1024 | LLM |
| service | サービス | 8 | 1024 | LLM |
| directory | 不審ファイル | 10 | 2048 | 異常スコア上位N件＋LLM |
| dns_cache | DNSキャッシュ | 8 | 1024 | LLM |
| netstat | TCP/UDP接続 | 10 | 2048 | 前処理＋LLM |
| prefetch | Prefetch | 8 | 1024 | LLM |
| appcompat_cache | ShimCache | 8 | 1024 | LLM |
| defender_quarantine | Defender検知 | 5 | 1024 | depth1ルール |
| ps_history | PowerShell履歴 | 15 | 1024 | LLM |
| hosts | hosts | 30 | 1024 | LLM |
| system_7045 | 新規サービス | 5 | 1024 | LLM |
| rdp_1024 | 外向きRDP | 20 | 1024 | LLM |
| bits_jobs | BITS | 5 | 1024 | LLM |
| security_1102/system_104 | ログ消去 | — | — | ルール＋収集品質 |
| task_141 | タスク削除 | — | — | ルール＋収集品質 |
| rdp_inbound/known_tools/userassist | 決定論所見 | — | — | ルール |

### 6-2. EventLog セクション（event_logs から取得）

| キー | 元ファイル | 処理 |
|---|---|---|
| system_7045 | Eventlog_System_7045_*.txt | parse_system_7045() で構造化 |
| security_1102 | Eventlog_Security_1102_*.txt | raw テキスト → ルールベース HIGH |
| system_104 | Eventlog_System_104_*.txt | raw テキスト → ルールベース HIGH |
| rdp_1024 | Eventlog_TerminalServices-RDPClient_Operational_1024_*.txt | parse_rdp_1024() で構造化 |
| defender_1116 | Eventlog_WindowsDefender_Operational_1116_*.txt | parse_av_quarantine() で構造化 |
| task_106 | Eventlog_TaskScheduler_Operational_106_*.txt | 構造化して登録イベントを解析 |
| task_140 | Eventlog_TaskScheduler_Operational_140_*.txt | 構造化して更新イベントを解析 |
| task_141 | Eventlog_TaskScheduler_Operational_141_*.txt | 構造化＋ルール評価 |

---

## 7. directory セクションの選抜ポリシー

directoryは全件を直接LLMへ送らない。Level 1とcanonical placement policyで候補化し、次の3層で選抜する。

```text
M0  強い決定論的根拠
    例: 二重拡張子、システムバイナリ名の配置外偽装、Startup実行体
    同一シグネチャ上限適用後の選抜を保証。通常枠超過は監査する。

M1  高リスクの書込可能配置にある実行体・スクリプト
    Users\Public、Windows\Temp、一般Temp、$Recycle.Bin、ドライブ直下、
    ProgramData浅層、AppData\Roaming直下。
    全件を会計し、既定で最大80、同一親8、同一配置32を層化選抜する。

R   その他のLevel 1／異常スコア候補
    固定100件上限を設けない。M0/M1後の通常枠残余をすべて使用する。
```

共通拡張子は`directory_policy.py`で管理する。主なスクリプトは`.bat/.cmd/.ps1/.vbs/.vbe/.js/.jse/.wsf/.hta`、実行体は`.exe/.dll/.scr/.com/.sys/.msi/.msp/.cpl/.ocx/.pif`である。

既定値:

```text
CHECKPC_DIR_MAX_LLM=200
CHECKPC_DIR_SIG_MAX=3
CHECKPC_DIR_M1_MAX=80
CHECKPC_DIR_M1_PARENT_MAX=8
CHECKPC_DIR_M1_PLACEMENT_MAX=32
```

M1が上限を超えた場合、黙って不存在扱いにせず、`coverage_degraded=true`、tier別総数・選抜数・繰延数、配置別選抜数をanalyzed metadataへ保存する。未選抜証拠はparsed raw検索の対象とする。

zip/rar/7zは従来どおりD分類としてLLM個別評価外とし、raw_directory系出力へ回す。ただしLevel 1で除外された全ファイルがraw_directory Markdownへ入るという意味ではないため、端末上の存在確認はparsed raw索引を使用する。

---


### N-4d. 同型パターン集約（案b / v3.59）

実運用（HOST-REF-03）で、C:\Windows\temp の GUID名 .tmp.js のような
「単一ソフトが量産したとみられる同型ファイル」が全件同点
（85点 = B基礎40 + SUSPDIR25 + SCRIPT20）となり、上位 DIR_MAX_LLM 枠を占有して
より低スコアの要確認エントリを raw 退避へ押し出す事象を確認した。
対策として「同一フォルダ × 同一ファイル名パターン」を1シグネチャとみなし、
シグネチャごとに代表 CHECKPC_DIR_SIG_MAX 件（既定3）のみ LLM 送付する。

- シグネチャ: 親フォルダ（小文字）＋ ファイル名の可変部（4文字以上の16進連なり・
  3桁以上の数字連なり）を '#' へ正規化したもの。拡張子チェーンは保持
  （.tmp.js と .tmp.exe は別型）。実装: analyze_section.py _dir_signature /
  _select_dir_llm_entries。
- 集約で空いた枠には、より低スコアの別シグネチャのエントリが繰り上がる
  （多様性の確保が目的）。DIR_MAX_LLM 上限・スコア降順は従来通り。
- 退避分は従来通り raw_directory へ全量保存し、⚠エントリで
  「何が何件 → 代表何件」を明示（黙って捨てない）。section_summary にも注記。
- CHECKPC_DIR_SIG_MAX=0 で無効（N-4c の単純上位切り出しと完全同一動作）。
- なお「スコア>0 がほぼ100%」自体は仕様（分類デフォルト B=基礎40点、0点は
  D分類のみ）であり、スコアは絶対評価でなく送付順位付けのための相対値。
- 回帰テスト: test_chunk_retry_dirsig.py N-4d-S1〜S3

## 8. ルールベース処理（LLM 未使用）

以下はコードで確定判定し LLM を呼ばない。

### defender_quarantine

v3.60: parse 段の datetime（1116イベントの Date:・UTC ISO形式）を評価エントリに
保持する。directory_scan 由来はファイル更新日時のため datetime_kind="更新" で
区別し、表示層が「（ファイル更新日時）」を併記する。SHA-1 重複集約時は全日時を
datetime_all に保持し、レポートは初回〜最終の範囲で表示（TZ-1 で JST 正規化）。
depth>=2 の LLM パスでも source_index 経由で元データの datetime が付与される。

- threat_name 有り → HIGH
- threat_name 空（directory_scan） → MEDIUM
- **隔離ストアのパス `...\Quarantine\Resource(s|Data)\XX\<SHA1>` から SHA-1 を抽出し、
  裸のハッシュとして iocs に設定（AV-VT）。** ResourceData/Resources の同一 SHA-1 は集約。
  → vt_post が hash 種別として VT 照合し `_vt.md` に結果掲載（--vt-key 指定時）。
  ※ Defender 1116 イベントログ自体にハッシュは無いが、収集済み directory データの
    隔離フォルダ名が元ファイルの SHA-1 である点を利用（batchtools 改修不要）。

### security_1102 / system_104
- ファイルが空 → `evidence_state=EMPTY_UNVERIFIED`（イベントなし／収集失敗を判別不能。不存在の根拠にしない）
- ファイルに内容あり → HIGH（証拠隠滅 T1070.001）

### task_141（タスク削除イベント / T-21-lite）
- ファイルが空 → `evidence_state=EMPTY_UNVERIFIED`（削除なし／収集失敗を判別不能）
- ファイルに内容あり → HIGH 注記（記録自体が異例。痕跡消去 T1070 の目視確認用）

### rdp_inbound（着信RDP / N-1）
- EID 21(LocalSessionManager)/1149(RemoteConnectionManager) を構造化（parse_inbound_rdp）
- 接続元が外部（グローバル）IP → HIGH（T1021.001 着信RDP・侵入経路）
- 接続元が内部（RFC1918 等）→ LOW（横移動の可能性・要確認）
- ソースが「ローカル」/console は parse 段階で除外
- ※ CheckPC のファイル名は "Manager"→"Mangaer" と誤記。patterns で誤記名に一致させる

### known_tools（決定論的検出 / N-3）
- **フィルタ層（suspicious/Level1）を通さず parse 済み全件を直接走査**し、allowlist 脱落を補完
- 既知ハックツール/マイナー名（mimikatz/xmrig 等）→ HIGH
- 遠隔操作デュアルユース名（radmin/rserver3/anydesk/ngrok 等）→ MEDIUM（要確認, T1219）
- C:\Windows\ 配下だが System32/SysWOW64/WID 等の正規でない場所のサービス → HIGH（T1543.003）
- Webルート（htdocs/wwwroot/inetpub）配下の .php/.aspx 等 → MEDIUM（Webシェル候補, T1505.003）

### LLM 結果 post-filter（_apply_post_filter）
LLM 出力後にルールベースで降格させる。取りこぼし防止のため
「明らかに正規」と断言できる条件に限定。

| セクション | 条件 | 処理 |
|---|---|---|
| task_scheduler | `\Microsoft\Windows\` 配下 + `rundll32.exe` + System32 DLL | HIGH/MEDIUM → **CLEAN** |
| task_scheduler | `\Microsoft\Windows\Windows Defender\` + MpCmdRun.exe | HIGH → **CLEAN** |
| task_scheduler | StateRepository + Windows.StateRepositoryClient.dll | MEDIUM → **CLEAN** |
| startup_folder | `~$*.dot/dotm/dotx`（Word 一時ロックファイル） | HIGH/MEDIUM → **CLEAN** |
| system_7045 | WPS Office + `AppData\Local\Kingsoft\` | HIGH → **MEDIUM** |
| system_7045 | Chrome Elevation Service + `AppData\Local\Google\Chrome\` | HIGH → **MEDIUM** |
| bits_jobs | Microsoft 正規配信ドメイン（*.delivery.mp.microsoft.com / windowsupdate 等）+ 通知コマンドなし | HIGH/MEDIUM → **CLEAN** |
| system_7045 | MpKsl{16進} + Defender 配下（Defender 動的署名サービス, N-2） | HIGH → **CLEAN** |

---


## 8-B. 重大度決定フロー（層の適用順序と対象マトリクス / v3.59）

スコア（HIGH/MEDIUM/LOW/CLEAN）に影響する処理層は複数ファイルに分散している。
v3.53 の不具合（task_scheduler が WL 対象から漏れ・プレースホルダ非対称）のような
「どの層がどのセクションに効いているか一覧できない」ことに起因するバグを防ぐため、
適用順序と対象を本節へ一元化する。
**対象セクション定数を変更する修正では、本マトリクスの更新をレビュー項目に含めること。**

適用順序（上から順）:

```
①L1   Level1フィルタ           depth=1のみ LLM送付前の選別        section_prompts.py LEVEL1_FILTERS
②SUS  suspiciousフィルタ       depth=1のみ フラグ付きのみ送付     analyze_section.py apply_suspicious_filter
③前   セクション固有前処理     netstatローカル宛CLEAN固定 等      analyze_section.py analyze()内
④評   評価本体                 LLM または ルールベース            analyze_section.py / section_prompts.py
⑤PF   post-filter降格          HIGH/MEDIUM→CLEAN（限定条件）      analyze_section.py _apply_post_filter
⑥WL   filepath whitelist降格   MEDIUM/LOW→CLEAN（HIGHは不変）     filepath_whitelist.py
⑦VT   VT必須条件付き降格 [2]   HIGH→MEDIUM（VT照合済&非malicious） vt_post.py apply_peruser_high_downgrade
⑧表   表示層の集約(スコア不変) M-1 MEDIUM集約 / RDP集約 / LOW集約  report_gen.py
```

セクション × 層 マトリクス（●=適用対象 / -=対象外）:

```
セクション            ①L1  ②SUS  ④評価               ⑤PF      ⑥WL  ⑦VT
--------------------  ----  ----  ------------------  -------  ----  ----
persistence_reg       ●    -     LLM                 -        -     -
startup_folder        -     -     LLM                 ●       ●    ●
task_scheduler        ●    -     LLM                 ●       ●    -
service               ●    -     LLM                 -        ●    -
directory             ●    -     LLM(+N-4c/4d選抜)   ●(M-2/床) ●   -
dns_cache             ●    ●    LLM                 ●(床)    -     -
netstat               ●    -     ルール③+LLM         ●(床)    -     -
prefetch              ●    -     LLM                 -        ●    -
appcompat_cache       -     ●    LLM                 ●(床)    ●    -
defender_quarantine   -     -     ルール(d1)/LLM(d2+) -        -     -
ps_history            ●    -     LLM                 -        -     -
hosts                 ●    ●    LLM                 -        -     -
system_7045           ●    -     LLM                 ●       ●    ●
security_1102         -     -     ルール              -        -     -
system_104            -     -     ルール              -        -     -
rdp_1024              ●    -     LLM                 ●(注記) -     -
bits_jobs             ●    -     LLM                 ●       -     -
task_141              -     -     ルール              -        -     -
psexec                -     -     ルール(T-23)        -        -     -
rdp_inbound           -     -     ルール(N-1)         -        -     -
known_tools           -     -     ルール(N-3)         -        -     -
userassist            -     -     ルール(M-4含む)     -        ●    -
```

補足:
- ⑧表示層はスコアを変更しない: M-1 MEDIUM集約（標準版のみ、_all版は全展開。
  v3.61: 永続化系 task_scheduler/startup_folder/service/persistence_reg/
  system_7045/bits_jobs は集約対象外＝常に個別展開）、
  RDP集約（rdp_inbound・同一接続元3件以上）、LOW集約。
- rdp_1024 の⑤PFは注記のみ（v3.61: GUID形式の接続先へ Hyper-V VM接続等の
  可能性を明示。スコア変更・降格は行わない）。
- ⑤PF の最終段（v3.66・全セクション）= reason-score矛盾フロア:
  悪性言及語（malware/マルウェア/悪性/C2）を含む CLEAN/LOW を MEDIUM へ床上げ
  （否定形は不発・冪等・_floor=reason_contradiction）。他のフロアで LOW 化された
  エントリへの複合昇格にも対応する。
- ⑤PF の「床」(v3.65追加分) = 可視性フロア: dns_cache は LLM の CLEAN を
  LOW へ床上げ（事前フィルタ通過ドメインの無害断定=confabulation を許可しない。
  実観測: online.autotranshub.com を「一般的なサービスドメイン」と無根拠断定→
  CLEAN）。netstat は LISTENING（識別子が「→ 0.0.0.0:0 / [::]:0」）の CLEAN を
  LOW へ床上げ。外向き接続のルールベース CLEAN 固定・T-29 LOW 固定とは整合。
- ⑤PF の「床」= 決定論 MEDIUM フロア（v3.64・昇格方向）: directory /
  appcompat_cache の CLEAN/LOW に対し、(i) 既知不審配置（Users\Public\
  Libraries, PerfLogs, $Recycle.Bin, Windows\Help/Fonts/Debug/Tracing）の
  実行ファイル、(ii) OSバイナリ名のシステム配置外存在、を MEDIUM へ昇格
  （HIGH/MEDIUM 不変・[フロア]注記・冪等）。LLM判定の揺らぎによる実害級の
  見逃し（A/Bで再現）への保険。⑥WLはフロア後に適用され、WL登録済みの
  正規ファイルは従来どおり CLEAN へ降格できる。
- 整合性の担保: ⑥WL対象 = filepath_whitelist.py _WL_TARGET_SECTIONS、
  ⑦VT対象 = vt_post.py targets（system_7045/startup_folder）、
  ⑤PF対象 = _apply_post_filter 内の section 分岐、と一致させること。
- netstat の③前処理: プライベート/ループバック宛CLEAN固定・エフェメラル
  LISTENING の LOW 固定・ループバックLISTENING の LOW 固定（T-29）。
- directory の③前処理: A/B/C/D分類 → N-4c異常スコア → N-4d同型集約 →
  上位 DIR_MAX_LLM 件のみ④へ。

## 9. DNS キャッシュ ホワイトリスト設計

suspicious=True にしない条件（取りこぼし防止のため慎重に管理）:

- `_DNS_KNOWN_GOOD_SUFFIXES`（後方一致）: microsoft.com / google.com / apple.com 等 + 
  adobestats.io / hstatic.io / fortinet.net / fortiguard.com / mozilla.net /
  pki.goog / ea.com / svc.ms / mshome.net 等
- `_DNS_KNOWN_GOOD_PATTERNS`（正規表現）: microsoftaik.azure.net のみ
- resolve が 127.x / ::1 → suspicious=False（hosts ファイル由来の自己解決）
- WL 済み + resolve 空 + NXDOMAIN → スキップ（ブロッキング hosts ノイズ除去）

**WL 化を意図的に見送ったドメイン:**
- `live.net` / `azure.net` 全体（C2 悪用リスク）
- `autotranshub.com`（不明ドメイン）
- `youmiuri.com`（タイポスクワット疑い）

---

## 10. 実行方法

### 単体実行

```bash
# 基本
python run_analysis.py <input> [オプション]

# 入力形式（自動判別）
python run_analysis.py CheckPC_LAPTOP_20260624.txt        # CheckPC テキスト直接
python run_analysis.py LAPTOP_20260624.txt                 # Base64 CAB (.txt)
python run_analysis.py LAPTOP_20260624.cab                 # CAB ファイル

# 主要オプション
--depth 1               # 解析深度（省略時=1）。1=Filtered Triage / 2=Broad Review /
                        # 3,4=試験機能（--experimental-depths 必須・v4.0 で再定義予定）
--output-dir ./output   # 出力先ディレクトリ
--context-file ctx.yaml # 追加コンテキスト（脅威情報）の YAML ファイル
-c "既知C2: evil.com"   # コマンドラインでのコンテキスト指定
--vt-key <KEY>          # VirusTotal API キー（スコア補正）
--vt-proxy <URL>        # VT 照合用プロキシ
--sections dns_cache    # 特定セクションのみ解析
```

### バッチ実行

```bash
python run_analysis.py --batch ./inputs [オプション]
```

対象ファイル: `inputs/` 内の `*.txt`（全形式）・`*.cab`
処理済み（`inputs/output/<NAME>_<STAMP>/` が存在するもの）は自動スキップ。

### コンテキストファイル（context_template.yaml）

```yaml
threat_actor: "Kimsuky"
malware_family: "Remcos RAT"
known_c2:
  - "evil.example.com"
  - "1.2.3.4:443"
known_iocs:
  - "SHA256: abc123..."
notes: |
  CTI レポートや社内情報の重要箇所をここにコピペ。
  800文字を超えると自動トリミング（警告あり）。
```

---

## 11. 出力ファイル

```
output/{HOSTNAME}_{STAMP}/
├── ingest_manifest.json                         # 入力・展開物のSHA-256/collection ID
├── parsed_{HOSTNAME}_{STAMP}.json           # Step3 構造化 JSON
├── analyzed_{HOSTNAME}_{STAMP}.json         # Step4 LLM 解析結果
├── analyzed_{HOSTNAME}_{STAMP}_vt.json      # Step7 VT 補正済み（VT 使用時）
├── correlation_{HOSTNAME}_{STAMP}.json      # Step5 相関分析結果
├── correlation_{HOSTNAME}_{STAMP}_vt.json   # Step7 VT 補正済み（VT 使用時）
├── report_{HOSTNAME}_{STAMP}.md             # 標準レポート（HIGH/MEDIUM 展開）
├── report_{HOSTNAME}_{STAMP}_all.md         # 全件レポート（LOW も展開）
├── report_{HOSTNAME}_{STAMP}_vt.md          # VT 補正済みレポート
├── report_{HOSTNAME}_{STAMP}_vt_all.md      # VT 補正済み全件レポート
└── report_{HOSTNAME}_{STAMP}_raw_directory.md  # directory D（zip等）目視確認用
```

---

## 12. 処理時間実績（depth=1）

| データセット | 特徴 | 実測時間 |
|---|---|---|
| HOST-REF-06 | Remcos 感染・日本語 | ~8 分 |
| HOST-REF-08 | 感染嫌疑 HIGH・日本語 | ~13 分 |
| HOST-REF-07 | 中国語環境・ブロッキング hosts | ~11 分 |
| SNOWLAPTOP | クリーン端末 | ~8 分 |

**section_workers=3 で並列実行（depth=1 のみ）。**
depth>=3 は section_workers=1（直列）。

---

## 13. 多言語対応

### 対応フィールド名

| セクション | 日本語 | 英語 | 中国語（簡体字） |
|---|---|---|---|
| system_7045 | サービス名/イメージ パス/アカウント名 | Service Name/Image Path/Account Name | 服务名称/服务文件名/服务账户 |
| defender_quarantine | 名前/パス/重大度 | Name/Path/Severity | URL から補完 |

### 対応ロケール

- **日本語 Windows**: 主要テスト環境。全セクション対応。
- **英語 Windows**: DNS キャッシュの `No records of type A` 対応済み。
  directory の英語ロケール日付形式（`MM/DD/YYYY HH:MM AM/PM`）対応済み。
- **中国語 Windows (簡体字)**: system_7045 の簡体字フィールド名対応済み。

---

## 14. 既知制限・設計上の決定事項

### LLM に送らない設計

| 対象 | 理由 |
|---|---|
| defender_quarantine（depth=1） | threat_name で即判定可能。LLM 不要 |
| directory D（zip/rar/7z） | パスを見れば分かる。LLM の付加価値なし |
| AppCompatCache（exec_flag） | Windows 10/11 では exec_flag が全件 N/A |
| directory C の超過分 | 78A ハッシュ系はアプリキャッシュが大半。上限3ch |

### VT filepath 照合（スコア変更なし）

ShimCache エントリのファイル名で VT 照合しても「ファイル名一致」は
ハッシュ未検証のため信頼性が低い。コンソールに表示するが
スコアは変更しない設計（T-40 検討保留）。

### OneDrive / AppData の WL 化

OneDrive AppData 配下を WL 化すると C2 として悪用されるケースを
見逃すリスクがある。現状は LLM に判定させる（T-27 現状維持）。

### Dropbox ポート（843/17600）の WL 化

APT34 等による Dropbox C2 悪用事例があるため WL 化しない（T-26 見送り）。

---

## 15. ToDo（未実装・継続検討）


> 完了済み項目の記録は CHANGELOG.md へ移設した（v3.59）。本節は未完了のみ。

### v3.68-rc2: depth=2 修正設計（実装済み・実機検証待ち）

旧depth=2の固定巨大チャンクは廃止した。解析前にcanonical raw mapを構築し、
決定論前処理と型付きctxを生成した後、`plan_depth2_selection()`が全セクションを
横断してselected / deterministic / deferredへ分割する。selectedのみを動的
`ChunkSpec`へ変換し、個別の出力上限、入力中略、oversize状態、raw source indexを
LLM transportまで保持する。

カバレッジはsource_index/source_id/canonical identifierのbindingを検証し、欠落partをキューで再帰分割する。
rev13では、親multi-entry応答で実際に返却されなかったraw rowがcoverage splitによってsingleton retryへ到達し、
入力1件・LLM返却1件・clean transport/parse・許容score・raw source_id/canonical identifierあり、の全条件を満たす場合だけ、
`source_index=0`、raw `source_id`、canonical `identifier`を原子的に再付与する。元LLM値と修復フィールドは監査metadataへ保持する。

multi-entry応答でvalid source_indexを主張したrowがsource_id/identifier bindingに失敗した場合、そのroot rowはrev13のcanonical repair対象外とする。coverage retry自体はlegacy互換で維持し、後続retryが従来規則どおり正しいbindingを返した場合だけ回復できる。singleton入力にLLMが2件以上を返した場合は一部採用せず`singleton_cardinality_violation`でfail-closed、0件はunevaluatedとする。
選抜済みだが回復不能なものは`selected_unevaluated`、方針上の選外は`deferred_by_policy`として区別する。

rev14ではDepth2 plannerそのものは変更せず、`depth1-depth2`比較にだけsignature-diversity representative認識を追加する。D1 HIGHのsource_idがD2 analyzedから消えても、同じsource_idのrawがD2 parsedに一意に存在し、そのraw indexがprovenance上`signature_diversity`だけを理由にdeferredであり、同じ`depth2_select._sig_generic()` signatureを持つrawがD2でselectedかつevaluated、さらにrepresentative source_idがanalyzed entryへ一意にbindingされる場合だけ代表scoreを参照する。代表にHIGHがあれば`signature_diversity_high_represented` REVIEW、代表最高がMEDIUMならD1 HIGHが非deterministicの場合だけ`signature_diversity_high_to_medium` REVIEWとする。D1 deterministic HIGH、代表LOW/CLEAN、代表なし、source binding曖昧、planner signature不一致、別deferred理由、raw evidence消失は従来FAILを維持する。これはD2が意図的に同一signatureを最大件数へ代表化した結果をcomparisonが二重にFAIL評価しないための比較意味論であり、`SIG_MAX_D2`や選抜score、source binding規則を緩和しない。

相関入力は固定section順で構成し、予算計算に使用した圧縮済みHIGH表現をそのまま
最終テキストへ使用する。最終テキスト自体について`est_tokens(text) <= budget`と
`high_unrepresented == 0`を検証する。

現在の予算プロファイル`v369-rc19-provisional`は実機校正中であり正式値ではない。rc17ではmandatory／section floorをtrimから保護し、必要時は明示的overrunを許容する。

### 今後の検討課題（2026-07-17 追加）
- チャット機能Lv.2は実装済み・既定無効。正式v3.69昇格前に実機受入試験を行う
- depth ごとのフィルタ見直し案（Level1 / suspicious フィルタの depth 別最適化。
  LEAN 採用で処理時間が約45%短縮されたことを踏まえ、depth=1 の絞り込み強度と
  送付件数上限のバランスを再検討する）
- LEAN の ON/OFF での出力結果を引き続き確認し、内容の調整を行う
  （GUI トグルで同一検体を両モード投入 → compare_analyzed.py でエントリ裁定、
  の定型手順。新しい劣化型が見つかれば決定論フロアで封鎖するサイクルを継続）

### A. パイプライン側 — 着手可能（Batchtools不要）

（v3.58時点で該当項目なし。A-MEDIUM・Eは分析官判断により削除。
T-23-psexecはv3.58で実装済み — 下記「完了（v3.58 / ...)」参照）

### B. 実機検証待ち — 正式v3.69昇格試験

| ID | 内容 |
|---|---|
| V369-1 | depth=1/2 × FULL/LEANを感染・クリーン・中国語・巨大directory端末で検証 |
| V369-2 | calibrate_budget.pyで仮値を集計し、P95/P99と未評価0件を確認 |
| V369-3 | 2ジョブ並行実行とチャット同時利用で証拠・ログ混入ゼロを確認 |

> v3.41で解決: PERF（CHECKPC_DIR_MAX_LLM=100実測）→ 実バッチで120実測し
> directory処理が約15分で完了したため、100への追加引き下げは不要と判断（現状維持）。

### C. Batchtools依存 — 後回し（方針）

| ID | 内容 | 前提 |
|---|---|---|
| T-25a/b | directory A/B パスへ certutil -hashfile でハッシュ付与→全不審ファイルのVT照合（隔離SHA-1のAV-VTは実装済、本件はその拡張）| CheckPCバッチ改修 |
| T-21-full | Security 4698/4699等によるタスク監査強化 | CheckPCバッチ追加収集 |
| T-23-WMI-full | Filter/Bindingを含むWMI結合評価 | CheckPCバッチ追加収集 |
| T-37 | appcompat ルールベース化 | exec_flag が全件N/A（CheckPC出力制約）|
| T-23-pending_rename | — | WL整備前提・痕跡薄 |

### D. 副次・現状維持 — 優先度低

| ID | 内容 | 理由 |
|---|---|---|
| N-6 | 量子化 Q3→Q4/Q5 | FP削減・要base117 VRAM実測・最適化枠 |
| T-40 | VT filepath basename IOC | 価値低（filepathエラーはv3.22で解消済）|
| T-42b | netstat chunk 16→20 | 要トークン実測（base117）|
| T-26/27 | Dropbox/OneDrive WL | リスク/効果薄で見送り |
| T-36b | directory zip絞り込み | raw_directory代替済み |

---

## 15-C. バックグラウンド成果物アーカイブ（v3.69-rc13）

- async endpointではファイル列挙・hash・ZIP圧縮を実行しない。
- `ArchiveManager`はbounded queueと単一workerを持ち、全ジョブ合計の`building`を1にする。
- 排他単位は`(job_id, kind)`。同一要求はdedupし、同一jobの異なるkind同時生成は拒否する。
- 対象jobはdone/error/cancelledのみ。error/cancelledは`terminal_partial`としてmanifestへ記録する。
- archive rootは`JOBS_DIR/{job_id}/archives`で、outputと相互に包含しない。
- validationは日常比較用、fullは完全output保存用。deferred provenance再構成はfullを要求する。
- 再利用判定はstat fingerprintによる高速化ヒューリスティック。完全性の根拠は作成時のsource file SHA-256とarchive SHA-256。
- symlinkを追跡せず、`O_NOFOLLOW`と`fstat`で列挙後差替えを検出する。
- source変更、timeout、disk不足、再起動を明示状態へ変換し、tmpを原子的に回収する。
- ジョブレジストリはプロセスローカルのため`WEB_CONCURRENCY=1`とinstance lockを強制する。
- rc9ではroot相互包含検査をsource walkより先に行い、timeoutを中央ディレクトリ照合・ZIP SHA-256・fsyncまで含める。
- `files_completed`ごとのstate fsync間引きは、実機full ZIPのGUI遅延測定後に判断する保留事項である。

状態遷移:

```
none -> queued -> building -> ready
                         -> error
```

API:

```
POST /jobs/{job_id}/archive
GET  /jobs/{job_id}/archive/status
GET  /jobs/{job_id}/archive/download
```

## 16. テスト

一括実行（P5 / v3.59 で統合）:

```bash
python3 run_all_tests.py        # 全 test_*.py を自動検出して実行
python3 run_all_tests.py -v     # 生出力も表示
```

- 本体と同じディレクトリおよび tests/ サブディレクトリの test_*.py を自動検出
  （v3.57〜58 の未統合8ファイルも拾う）。
- 実データ（/home/claude/extract、CHECKPC_TEST_EXTRACT で変更可）が無い環境では
  実データ依存テストを SKIP と明示する（FAIL 扱いしない）。
- KNOWN_FAILURESは通常開発実行では区別して表示するが、`--release`では1件でも不合格。
- 実データ未配置時のSKIPも`--release`では不合格。
- 正式v3.69の受入条件はKNOWN_FAILURE=0 / ERROR=0 / SKIP=0。

v3.69-rc17の実データなし環境での実測は PASS=1999 / 新規FAIL=0 / ERROR=0 / SKIP=5。詳細は`TEST_RESULTS.md`を参照する。
5ファイルのSKIPは実データ未配置による。正式昇格時はbase117で`--release`を実行し、
全テストを実行する。


---

## 16-B. v3.30〜v3.40 追加サブシステム設計

### 16-B-1. 感染タイムライン（timeline.py / T-TL 系）
- **T-TL1〜3**: 9 セクションを LLM 非依存の決定論で抽出→時系列ソート→phase 付与→所見突合で不審(*)標記。
- **TL-A**: parsed.json の `sections` と `event_logs` の両方をマージ（7045/rdp_inbound 等は event_logs 側）。
- **TL-B/C**: スラッシュ区切り・秒なし・ダブルスペース等の時刻形式に対応、パス抽出の空白切れ・汎用所見を除外。
- **T-TL4**: run_analysis に配線し `report_*_timeline.md` / `_vt_timeline.md` を自動出力。
- **T-TL5**: LOW 実行痕跡（userassist/prefetch）を不審/HIGH/MEDIUM の ±30 分にフォーカスして抑制（`full=True` で全件）。
- **T-TL6**: 不審窓を単一 min〜max でなく時間ギャップ（既定 24h / env `CHECKPC_TL_CLUSTER_GAP_H`）で「インシデント窓」にクラスタ化。HIGH/MEDIUM 含む窓を重大度→新しい順で表示、LOW*のみは件数集計。

### 16-B-2. 時刻 JST 正規化（TZ-1 / timeline._parse_ts）
- 末尾 `Z`/`+00:00`（UTC）→ +9h、明示オフセット ±HH:MM → JST(+09:00) 正規化、マーカー無しはローカル(JST)扱い。
- イベントログ(UTC)と filesystem/registry(JST) の混在で最大 9h ずれていた年表を是正。
- 小数秒除去を時刻部限定にし、ドット区切り日付（YYYY.MM.DD）の破壊を修正。
- **限界**: `Z` を欠くイベントログ時刻（ホストにより実体 UTC の場合あり）は自動変換しない（要検証）。

### 16-B-3. 決定論フォールバック移植（R-3/R-4 / report_gen）
- `derive_malware_family`（Defender 検知名 `Platform:Type/Family!suffix` から抽出）／`derive_suspicion_floor`（HIGH>0→HIGH 等）を report_gen に集約し、correlate.py と run_analysis 双方から共有。
- LLM が None/Unknown を返した時のみ補完し、`_meta_flags` に provenance を残す。

### 16-B-4. FP 削減（クリーン端末の嫌疑是正）
実測で FP 主因は known_tools でなく、userassist(78)/directory(51)/netstat(22) と system_7045 の HIGH 5 件だった。取りこぼし防止のため「削除でなく降格＋allowlist」を原則とする。
- **[3]（analyze_section）**: `_KT_WIN_OEM_SVC_RE`（C:\Windows\配下 OEM: Conexant/Realtek/Waves/Nahimic）＋`_KT_SVC_PERUSER_LEGIT_RE`（既知 per-user updater/同期）を known_tools サービス判定から除外。偽装（別パス同名）は検出維持。
- **[2]（vt_post.apply_peruser_high_downgrade）**: system_7045/startup_folder の HIGH を「ベンダ/アドイン allowlist 一致 かつ VT 照合済み かつ malicious でない」時のみ MEDIUM 降格。VT-clean は積極証拠にせず malicious を降格拒否ゲートに使用（ファイル名検索の限界対策）。VT malicious/未照合/allowlist 非該当は HIGH 維持（HWiNFO BYOVD 等を取りこぼさない）。
  **[2]拡張（v3.41）**: 実バッチでOfficeアドイン枠（Zotero等）が一度もMEDIUM降格されない不具合を発見。原因は `_classify_ioc` の filepath IOC対象拡張子リストがOfficeマクロ拡張子（.dotm/.dot/.xlam/.xla/.ppam/.xlsm）を含んでおらず、VT照合自体（`_vt_results`）が発生しないため条件（VT照合済み）を満たせなかったこと。拡張子リストに追加して修正。per-user/Tempサービス枠（.exe等）は元々正常動作していた。
  なお、filepath型IOC（ファイル名検索・実ファイルのハッシュ未検証）の malicious 判定は hash型と同じ重みで降格拒否ゲートに使われる仕様を維持（HOST-REF-02でVT名前一致のみのHIGH維持事例を確認・目視で実害なしと判断のうえ現状維持と決定）。
- **M-1（report_gen）**: 標準版レポートで MEDIUM を reason シグネチャ別に集約（VT malicious/suspicious は個別展開）。`_all`(full) は集約せず全展開。検出データは不変。
- **M-2（analyze_section post-filter directory）**: 既知 benign 一時ファイル（wct/ns*/~DF/CR_/amc/TS/set の *.tmp・GUID.tmp）を MEDIUM→LOW。実行体は対象外。
- **M-4（analyze_section userassist）**: Downloads/デスクトップ実行体を MEDIUM→LOW。Temp/$Recycle/Public/隠し/非Cドライブ直下は MEDIUM 維持、スクリプト＋不審フォルダは HIGH 維持。
- **Q2（directory A 分類）**: 二重拡張子パターンを分割。exe/scr は場所問わず A、.dll は「パス付き かつ 信頼配置(System32/SysWOW64/WinSxS/Program Files 等)でない」時のみ A。正規名前空間 DLL（Windows.Data.Pdf.dll 等）の誤昇格を解消。

### 16-B-5. filepath whitelist 統合（提案B / filepath_whitelist.py）
- J-CRAT 蓄積の `master_filepath_whitelist`（3387 件）を照合エンジン化。完全一致は set（O(1)）、`%envvar%`/`*`/先頭 `:\`（ドライブ非依存）は正規表現に変換。
- `apply_whitelist_downgrade`: 対象 7 セクション（directory/prefetch/appcompat_cache/userassist/startup_folder/service/system_7045）の MEDIUM/LOW を CLEAN 降格。**HIGH は絶対に触らない**（正の悪性シグナル優先）。WL 未在時は no-op。
- 配置: `filepath_whitelist.py` と同じディレクトリ（analysis 直下）の `master_filepath_whitelist.txt`(UTF-8)。env `CHECKPC_FILEPATH_WHITELIST` で差替可。
- **MEDIUM 削減効果は限定的（実測 ~2%→ほぼ 0%）**: flagged される MEDIUM/LOW は Temp/AppData 等の非典型配置で、WL（典型正規配置）と非重複のため。監査可視化のためレポートヘッダに「WL抑制: N件」を表示（[任意2]）。
- Phase3（LLM 送付前フィルタ）は削減余地 1〜2%・全件照合 59 秒で逆効果のため**見送り**。

### 16-B-6. netstat 解析不全対策（案A）
- 旧 `chunk=16 × max_tokens=1024`（64tok/entry）で 16 件×~130tok=~2080tok が budget を超え JSON 切断→解析不全が多発。`max_tokens 1024→2048 / chunk 16→10`（205tok/entry）で解消。

### 16-B-7. CAB / ShimCache 周辺の堅牢化
- **CAB 残骸**: 直接 .cab 入力の展開先を入力と同じ場所でなく work_dir(_tmp_decode) 配下へ。後段の「run_dir 移動→_tmp_dir 削除」で回収され、入力フォルダに残骸を残さない。
- **ShimCache 照合**: CheckPC↔AppCompatCache の対応付けを、ロケール依存の曜日文字（中国語 "周三" 等）や展開時の文字化けを除去した ASCII 安定キーで行う（`_shim_match_key`）。
- **ShimCache 文字化けパス**: 照合したファイルを ASCII 安全な固定作業パス（appcompat_input.txt）へ複製し、出力 CSV 名も非 ASCII 除去してから python2.7/nkf に渡す。
- **ShimCache 診断**: 「パーサ未検出」「AppCompatCache 未照合」「AppCompatCache が空（正常）or 未対応形式」を区別して表示。python2 は print を STDOUT に出すため STDOUT/STDERR 双方を表示。ShimCacheParser のパスは env `CHECKPC_SHIMCACHE_PARSER` で単一指定可。
- **確認事項**: AppCompatCache が空（52byte=ヘッダのみ・エントリ0件）の端末（新規/クリア直後/VM）は CSV が出ないのが正常。ShimCacheParser 自体は Win10 Creators Update(RS2, stats 0x30/0x34) までの形式に対応。

## 16-C. 解析結果チャット機能（v3.71-rc6 Threat-Intelligence Redesign）

### 目的
チャットをCheckPC内部sectionの閲覧UIではなく、案件内証拠をThreat Intelligence観点で
検索・横断相関・prevalence確認・時系列確認する支援レイヤとして扱う。
Qwen2.5-Coderへ証拠格納場所やraw/analyzedの選択を委譲せず、Python側で決定論的に処理する。
parser、analyze、correlate、Depth1/2、comparison、formal provenanceは変更しない。

### LLM公開tool
```text
investigate_local
  action=search | summary | timeline
  query=search/timelineで使用
  limit=Python hard capあり

vt_ioc_lookup
  分析官が現在の発言で外部TI/VirusTotal照会を明示した場合のみ
```
旧`get_section` / `get_entry_detail` / `search_keyword` / `search_directory_evidence` /
`list_high_medium` / `get_timeline` / `list_directory_files` / `cross_host_search`は
v3.71-rc1では内部compatibility handlerとして残すが、LLM tool schemaへ公開しない。
モデルが旧tool名を生成してもPython側で`tool_not_public`として非dispatchとする。

### local investigation scope
非空folderがある場合、query開始時のjobs metadata snapshotからcurrent jobとexact same-folder jobだけを
対象とする。folderなし・metadata異常時はcurrent hostだけへfail-closedする。LLMにscope選択引数を与えない。
案件横断はローカル読取であり通常機能とし、外部送信権限とは分離する。

### deterministic multi-label Evidence Pivot
`search`はqueryを1つのentity typeへ排他的分類しない。hash/IP/FQDN/絶対path等の高信頼型は優先しつつ、
filename、hostname、process、service、task、registry、Defender threat name、任意keyword等の複数namespaceを
決定論的に検索する。analyzed hitがあっても必要なraw evidenceを抑止しない。

結果ではcurrent/other hostを分離し、最低限次を会計する。
```text
observed_host_count
searchable_host_count
case_host_count
unavailable_host_count
coverage_complete
```
`unavailable`をabsenceとして扱わない。prevalenceはdistinct hostを単位とし、analyzed entry数を分母・分子に使わない。


### rc8 authoritative answer facts / final grounding

correlation exact-positive prevalenceでcoverageがcompleteな場合、Pythonが算出した`matched_host_count`、`prevalence`、`matched_hostnames`を`answer_facts`としてtool resultのverbose hit配列より前へ配置する。tool outputは3000文字でboundedされるため、集計値を後段へ置いてはならない。

`answer_facts.authoritative=true`の結果を取得したturnでは、追加tool roundへ進まずfinal-only callへ移行する。final groundingのcontrol noteへ昇格できるのはPythonが生成した件数・coverage等のbounded numeric metadataだけであり、生hostname/path/command line等の証拠値は引き続きuntrusted tool result内に留める。LLMは個別hitsを再集計せず`matched_host_count`を件数回答に使用する。

### rc7 single-pass correlation prevalence

- 案件prevalence / previous-result follow-upのcorrelation exact-positive fast pathは、`summary()`先行＋再scanを廃止し、同一scopeを1回だけ走査する。
- 1パス内でcorrelation schema、存在するanalyzed/parsed meta pair、hostname、infection_suspicion、malware_family、exact positive IOCを同時に確認する。
- filename queryはbare filename exactとfull-path basename exactを同一entityとして扱うが、substring一致は許可しない。full-path queryはfull path exactのみで、同basenameの別pathへ広げない。
- 同一hostにbare filenameとfull pathの両方があってもdistinct-host prevalenceでは1台として数える。
- deadline到達時は実際に1パスで検索できたhost数をcoverage分母とし、full scope未完了なら`prevalence=null`。別処理のcomplete flagを流用しない。
- correlation exact-positive 0件はabsence oracleにせず、従来どおりEvidence/Directory searchへfallbackする。

### rc6 explicit literal grounding / correlation positive prevalence

- analyst messageにfilename/path/hash/IP/FQDNの明示literalが1個ある場合、LLMが`*.ext`等へ一般化してもPython側のeffective queryはそのliteralへgroundする。
- `LNKファイルを10個`のように明示literalがない列挙要求ではrc5の`*.lnk → .lnk`限定正規化を維持する。
- 「案件内の何台」「どのホスト」等のprevalence intent、またはprevious-result follow-upでは、correlation `correlated_iocs`のexact positive matchをdistinct-host集計へ利用できる。
- correlation exact-positiveが0件の場合は不存在と判断せず、通常Evidence/Directory searchへfallbackする。
- correlation fast pathのmatched job IDsは既存bounded evidence ledgerへ保存し、`そのホスト名`等のfollow-up scopeへ再利用する。

### mixed v3.69 / v3.70 / v3.71
v3.69 schema 2.0とv3.70/v3.71 schema 2.1はchat専用normalizerでnormalized entity / raw observationへ
寄せる。v3.70 Task140等のsemantic groupingとv3.69 one-to-one representationをanalyzed entry数で比較しない。
正式artifact自体を別version形式へ変換しない。未知schemaは`unsupported_schema`としてunavailableにする。

### Chat Evidence Cache
job rootの`chat_cache/chat_evidence_v1.sqlite`へ再生成可能な非formal cacheを置く。正式`output/`を変更せず、
archive対象にも含めない。source identity、pipeline/schema、normalizer version、builder package identity等を保持する。
新規jobはcore evidenceを利用し、旧jobの巨大directoryは案件全台を初回同期buildしない。既存directory indexを優先し、
必要なcurrent legacy hostではbounded streaming fallbackを許可する。検索不能hostはcoverageへ反映する。

### Evidence relation / timeline
初版では汎用Evidence Graphを作らない。同一record内で明示されたDNS→IP、service→configured image、
task→configured action、registry→value data、Event 7045→service image等の直接関係だけを返す。
relationshipは`basis` / `confidence` / `causal`を保持し、原則`causal=false`。PID一致やpath一致だけで因果・同一fileを断定しない。
timelineもtimestampのsource semanticsを保持し、時間的近接を因果へ変換しない。

### Cross-turn evidence ledger
full tool resultを会話履歴へ永続化せず、`chat_cache/evidence_ledger_v1.json`へboundedなresult/evidence refs、
scope digest、host coverageを保持する。「その4台」等のfollow-upは必要な証拠だけPython側で再解決する。
`DELETE /chat/{job_id}`ではhistoryとledgerを削除し、再利用可能なindexと監査ログは保持する。

### Tool loop
通常1～2 round、hard maximum 3。同一ターンのcanonical tool name + canonical JSON argumentsが一致するcallは
2回目をdispatchせず`duplicate_tool_call`とする。旧非公開tool名もdispatchしない。

### 外部TI / VT
VT境界は従来どおり、hash・global public IP・FQDNだけを許可し、URL/path/filename/email/private IP等を通信前拒否する。
さらにv3.71では、現在のanalyst発言にVirusTotal/外部TI/レピュテーション等の明示意図とexact IOCがある場合だけ許可する。
local検索で発見したIOCだけを根拠に自動送信しない。proxy/cache/rate-limit/429/secret redaction/auditを維持する。

### Prompt injection / system layer
証拠・tool resultは`<BEGIN_UNTRUSTED_TOOL_RESULT>`境界で非信頼データとして扱い、境界tag neutralizationを維持する。
correlation由来自然言語やraw evidenceをsystem instructionへ直接埋め込まず、systemはpolicy/behaviorを中心とし、
evidenceはtool resultとして渡す。

### GUI / policy
`simple/standard/detailed`、Lv.1/Lv.2、「読み取り専用」というユーザー概念を廃止する。
GUIでは案件scope/host数と外部TI ON/OFFを表示する。内部互換の`chat_lv2_policy`は当面保持し、
`local_vt_ioc`だけを外部VT許可として扱う。local investigationのkill switchとVT kill switchは分離する。

### v3.71-rc1非目標
```text
汎用Evidence Graph / graph DB
多段relation traversal
自動actor attribution
ATT&CK自動推測
新malware score
STIX/MISP統合
VT Graph全面crawl
parser/analyze/correlate/Depth/comparison/provenance変更
```

## 16-D. 【完了・v3.57 / v3.60拡張】Defender検知ログ集約＋不審フォルダDirectory抽出

> v3.60: 各ファイル/コマンド行の直下に「└ 検知: 初回 〜 最終 (JST・n件)」を
> 追記する（既存行は不変の追記行方式。単一検知は日時のみ、日時なしは追記しない）。


分析官からの要望を実装。詳細は「完了（v3.57 / 16-D: ...)」参照（セクション15）。
実装は `defender_dir_report.py`（新規）。当初の想定形式（下記）から、実データ
検証で「・コマンド」の実体が Process Name だけでなく `CmdLine:_` 形式の
実コマンドライン検知（COM hijack等）も含むことが判明し、両方を統合する形に
拡張した。分析官コメント欄は要望により省略。

```
■Defender検知ログ
〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓
・ファイル
<検知された全ファイルパスを重複排除して列挙>
・コマンド
<検知されたコマンドライン/実行プロセス名を重複排除して列挙>
〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓

■不審フォルダ
〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓
・<ホスト名>
  <検知ファイルが所在するフォルダパス>
  <dirコマンド相当の一覧（タイムスタンプ・サイズ・ファイル名）>
〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓〓
```

## 16-E. 【保留】推定タイムライン（LLM生成）の精度改善（v3.55で本体から分離、着手時期未定）

v3.55でレポート本体からは削除し決定論的なtimeline.py出力への参照に置き換えたが、
LLMによる「推定タイムライン」（correlate.pyのcorrelated_iocs/timeline出力）自体の
情報の雑さ（何が原因で品質が低いのか、深掘り調査は未着手）を改善する課題は
別途残っている。着手する場合の調査観点（未着手・アイデアレベル）:
- 現状のcorrelateプロンプトのtimeline出力フォーマット・指示内容の見直し
- timeline.py（決定論版）とLLM推定版で情報の粒度・信頼度がどう異なるか比較検証
- 将来的に両者を統合する設計（決定論版をベースに、LLMは「解釈・意味付け」のみ
  補うハイブリッド方式等）も検討の余地あり

---





## 17. バージョン履歴

CHANGELOG.md へ移設した（v3.59 / P4）。以後の履歴は CHANGELOG.md にのみ追記すること。

## 24. rc16 validation archive命名とidentity gate

validation archiveはingest manifestおよびanalyzed成果物の`analysis_mode`から命名する。LEANは`validation_LEAN.zip`、FULLは`validation_FULL.zip`とする。job設定、成果物、runtimeのversion/schema/profile/modeが一致しない場合は生成を拒否する。full archiveは`full.zip`を維持する。


## 25. rc18 Depth2 evidence preservation and generalization

### 25-1. 選抜前mandatory

`startup_folder`のOffice startup macro候補は、製品名ではなく次の属性でmandatory化する。

```text
source=office_startup
suspicious=true
extension=.dot/.dotm/.xlsm/.xlam
basenameが~$で始まらない
```

mandatory候補はLevel1 allow-setへunionし、section cap／予算trimから保護する。

### 25-2. section floorとplanner maximality

mandatoryとsection最低代表枠は`protected_floor`としてtrimから保護する。超過中はbounded small-batch trimを行い、予算境界では1件単位へ切り替える。予算内へ戻った後は優先順位順にbackfillする。

```text
planner_trim_iterations
planner_trim_dropped
planner_backfill_iterations
planner_backfill_added
unused_budget_tokens
plan_is_maximal
maximality_addable_candidates
```

`plan_is_maximal=true`は、未選抜の適格候補を1件追加して予算内に収められないことを意味する。固定の利用率だけでは合否を決めない。

### 25-3. 全件繰延表示

`raw>0 / selected=0 / deterministic=0 / deferred>=raw`のsectionは「所見なし」にせず「全件繰延・未評価」と表示し、安全確認済みではないことを明記する。

### 25-4. 汎用証拠分類

user-writable領域の実行可能ファイル痕跡は、basenameではなくpath classとartifact typeで高優先選抜し、LOW/CLEANに対してMEDIUM floorを適用する。HIGHは降格しない。特定製品名、特定IP、過去実機source_idを本番条件へ使用しない。

netstatの外部IP、非標準remote port、対象state、process未帰属はMEDIUM floorとする。HIGHはTI、既知悪性IOC、永続化相関、反復、不審process/service、blacklist等の追加根拠へ委ねる。

### 25-5. score schema recovery

scoreは`HIGH/MEDIUM/LOW/CLEAN`に限定する。不正値を検出したchunkは1回再試行し、再失敗時はentryをMEDIUMへ安全縮退する。

```text
score_raw
score_normalization_warning=invalid_score
schema_degraded=true
```

該当entryはreport、correlation、compareから欠落させない。

### 25-6. raw照合と比較

raw証拠はstable source_id、canonical key、raw indexの順で解決する。compareはsame-depthとcross-depthを区別し、証拠消失とinvalid scoreを自動不合格とする。cross-depthのdeterministic HIGH劣化も自動不合格とする。


### 比較会計の定義
比較監査では `dedup前の入力オカレンス数` を保持し、重複排除後件数との会計閉性を確認する。

## v3.69-rc26 監査境界設計

### parsed coverage
`sections`と`event_logs`のlist-backed raw sectionは、明示的補助入力allowlistを除き、analyzedに同名sectionが存在し完全provenanceを持たなければならない。allowlistは`tasklist`のみで、ホスト名、件数、source_idによる動的例外は設けない。raw_count=0も検査対象とする。

### derived evidence
raw textに対するルール判定は、ファイル全体を1件のatomic evidenceとしてstable source_idを作成し、deterministic stageへ計上する。derived findingは由来sectionとraw indexを保持する。comparison provenance schemaは1を維持し、`provenance_scope`でraw-backedとderivedを区別する。

### package identity
`SHA256SUMS.txt`全件一致を解析開始条件とする。manifest自体のSHA-256をpackage identityとして成果物へ記録する。package identityは推論条件の`runtime_fingerprint`へ混在させず、同一build比較で別途一致を要求する。

### reproducibility scope
機械比較はparsed/analyzedに限定する。correlation/report/ingest manifestは拡張証跡bundleに含めるが、時刻や一時パス等の正規化規約が確定するまではcomparison resultの対象外と明示する。

### v3.70 upgrade baseline
`UPGRADED_FROM_VERSION=3.69`を記録し、正式v3.69の外部設定・秘密ファイル拒否・検証済み数値予算を継承する。
