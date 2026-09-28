# CheckPC APT Analysis Pipeline 設計書 v3.71

最終整理: 2026-09-28

## 1. 位置付け

CheckPC v3.71 は、v3.70 rev14-formal の解析パイプラインを基準に、解析結果チャットの Threat Intelligence 機能と、その外部送信境界を再設計した正式リリースである。

正式版の基準 candidate は `v3.71-rc16` とする。GitHub 取り込みにあたって candidate runtime code は機能変更せず、candidate 時点の manifest / SHA / validation 状態を改変しない。

## 2. 基本原則

1. **取りこぼし防止を優先する。** 最終判断を単一の LLM verdict に依存させない。
2. **LLM を信頼境界に置かない。** scope、coverage、provenance、外部 TI 送信可否は Python 側で決定する。
3. **証拠を命令として扱わない。** raw evidence、追加 context、tool result は非信頼入力として system instruction から分離する。
4. **identity / provenance を fail-closed にする。** pipeline version、schema、package identity、run provenance が不整合なら正式 gate を通さない。
5. **コードと秘密設定を分離する。** 認証情報、TLS 鍵、VT API key、proxy credential は配布物外の EnvironmentFile で管理する。
6. **rollback 可能性を維持する。** 稼働コードと外部 env は stable symlink をセットで切り替える。

## 3. 解析フロー

```text
CheckPC CAB / TXT
  -> ingest / decode
  -> parse
  -> deterministic / L1 preprocessing
  -> analyze
  -> Depth2 selection (必要時)
  -> correlate
  -> report / timeline / PDF
  -> server / GUI
  -> analysis chat
```

解析 core は v3.70 rev14-formal を基準とし、v3.71 の主変更点は chat / TI 境界である。

## 4. Chat Threat Intelligence 設計

### 4.1 LLM 公開 tool

主要な tool surface は次の2系統に集約する。

```text
investigate_local
vt_ioc_lookup
```

`investigate_local` は案件内証拠の探索・横断確認を担当し、`vt_ioc_lookup` は明示的に許可された IOC の外部 TI 照会だけを担当する。

### 4.2 案件 scope と横断性

- 案件 scope は server / Python 側で確定する。
- mixed-version job は normalization を経て扱う。
- host prevalence と coverage は tool result の件数ではなく、案件全体の定義済み母集団に対して算出する。
- Directory 等の巨大 raw evidence は bounded search / SQLite index を用い、初回 chat で案件全台を同期 index 化しない。

### 4.3 外部 TI authorization

外部 TI へ送信できる IOC は、**current turn で明示肯定された IOC** に限定する。

以下は authorize しない。

- 「確認しないで」「調べないで」等の否定 directive
- `do not, under any circumstances, check ...`
- `never, ever, ...`
- `please do not, for any reason, ...`
- 「確認するのはやめて」
- 「検索するのはやめて」
- 「調べてほしくない」
- 「確認してほしくない」
- 肯定・否定が混在し、対象 IOC の対応が曖昧な directive

rc16 では、英語の comma 境界と日本語の肯定 action 部分一致に起因する false authorization を fail-closed 化した。

## 5. Provenance / Comparison / Release gate

正式評価では、少なくとも次の 4 mode を区別する。

```text
D1 LEAN run1
D1 LEAN run2
D1 FULL run1
D2 LEAN run1
```

比較軸:

```text
reproducibility
cross-version
full-lean
depth1-depth2
```

主要 gate:

- `validate_run_provenance.py`
- `validate_semantic_binding.py`
- `compare_runs.py`
- `comparison_approval.py`
- `comparison_release_gate.py`
- release-mode regression

候補 artifact の正式昇格記録と、候補自身の validation metadata は別物として扱う。候補 snapshot の metadata を後から書き換えて監査証跡を壊さない。

## 6. 運用・秘密情報

標準 stable link:

```text
/opt/llm/analysis-current
/opt/llm/checkpc-pipeline-current.env
```

秘密値・認証情報・TLS 鍵・VT API key・proxy 認証情報は repository / package に格納しない。

詳細な更新手順は `docs/operations/CheckPC_汎用バージョンアップ手順書_v1.0.md` を参照する。

## 7. v3.71 candidate snapshot

正式版の基準は `v3.71-rc16`。candidate package は正式昇格前の状態を保持するため、内部では `RELEASE_STATUS=validation-pending` の記録が残る。

この repository では、その値を「正式リリース未完了」の意味に読み替えず、**候補 artifact を固定した時点の metadata** として扱う。正式リリース決定は `docs/releases/v3.71/RELEASE_NOTES.md` に記録する。
