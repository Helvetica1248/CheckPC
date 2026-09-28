# CheckPC APT Analysis Pipeline v3.71

CheckPC が収集した Windows 初動調査データ（CAB/TXT）を、ローカル LLM と決定論的ルールで解析し、ホスト単位のレポート、横断相関、タイムライン、解析結果チャットを生成するパイプラインです。

**v3.71 は 2026-09-28 に正式リリース完了としました。** 実装系譜は `v3.70 rev14-formal` → `v3.71-rc1 ... rc16` で、正式版は最終 candidate `v3.71-rc16` を基準にしています。

## リポジトリ構成

- `pipeline/` — v3.71-rc16 を基準とする公開用コード・テスト・必要資源
- `docs/releases/v3.71/SOURCE_IMPORT.json` — 元candidateと公開ソースのファイル別対応・検証

- `DESIGN.md` — v3.71 の現行設計と安全境界
- `CHANGELOG.md` — v3.71 正式化と主要変更履歴
- `INSTALL.md` — 配置・更新の入口
- `docs/releases/v3.71/RELEASE_NOTES.md` — 正式リリース記録
- `docs/releases/v3.71/SOURCE_DELTA.md` — v3.70 rev14-formal からの主要 source delta
- `docs/releases/v3.71/CANDIDATE_SHA256.txt` — 基準 candidate 配布 ZIP の SHA-256
- `docs/releases/v3.71/v3.71-rc16_変更概要.md` — rc16 限定修正の一次整理
- `docs/releases/v3.71/v3.71-rc16_実装・検証結果_20260824.md` — rc16 focused 検証記録
- `docs/operations/CheckPC_汎用バージョンアップ手順書_v1.0.md` — stable symlink 方式の更新手順
- `docs/operations/GUI_USER_GUIDE.md` — GUI 利用ガイド

## v3.71 の主要変更

v3.71 では解析本体よりも、解析結果チャットの Threat Intelligence 境界を重点的に再設計しました。

- LLM 公開 tool を `investigate_local` と `vt_ioc_lookup` に集約
- 案件 scope、mixed-version normalization、coverage、distinct-host prevalence を Python 側で決定
- raw Directory 等の巨大証拠を bounded search / SQLite index で扱い、初回チャットで案件全台を同期 index 化しない
- VirusTotal 等の外部 TI 送信は、current turn で明示肯定された IOC だけを authorize
- 否定文、混在 directive、複数 IOC、英語 comma 境界、日本語「～するのはやめて」「～してほしくない」等を fail-closed 化
- parser / analyze / correlate / Depth1/2 / comparison / provenance は v3.70 rev14-formal を基準に維持

## 正式版と rc16 candidate について

v3.71 正式版は rc16 candidate を基準にしています。

rc16 は正式昇格前に固定された candidate なので、配布物内部の `version.py` / `release_manifest.json` / 検証資料には当時の `validation-pending` が残っています。これらを GitHub 取り込み時に書き換えると candidate package の SHA・manifest・監査証跡を壊すため、書き換えません。

正式リリース状態と candidate metadata の関係は `docs/releases/v3.71/RELEASE_NOTES.md` に記録しています。

## 配布物の完全性

基準 candidate ZIP:

```text
checkpc_pipeline_v3.71-rc16_20260824.zip
SHA-256:
2d35411c7c0e7715fa63bfe15350152f5289c6580890d9ef86f4b30ea8f22227
```

GitHub 取り込み前に clean extraction で package manifest と focused regression を再確認し、460 / 460 PASS を確認しています。

> GitHub 連携経由ではバイナリ配布 ZIP を repository commit に直接取り込めないため、この repository には正式版ドキュメントと candidate の provenance / SHA を格納し、配布 ZIP 自体の hash を固定しています。candidate 配布 ZIP の内容を正式化のために再生成・後編集はしていません。

## セキュリティ方針

- 取りこぼし防止を優先し、LLM だけで最終判定しない
- 証拠、追加 context、tool result は非信頼入力として境界化
- 外部 TI 送信は明示許可された IOC だけを対象とし、曖昧な自然言語は fail-closed
- 秘密値・認証情報・TLS 鍵・VT API key・proxy 認証情報は package / repository 外の EnvironmentFile で管理
- 正式更新はコードと EnvironmentFile を stable symlink でセット切替し、rollback 可能性を維持

詳細は `DESIGN.md` と汎用バージョンアップ手順書を参照してください。


## 開発用ソースの取り込み（2026-09-28）

`pipeline/` に元candidateのPythonコード146ファイルと必要資源11ファイルを取り込みました。独立した `SHA256SUMS.txt` を含め、158ファイルです。

解析・判定・検索等の実装ロジックは変更していません。公開用の処理として、実端末名・収集日時・実ユーザー名に由来するテスト識別子、コメント、docstring、環境固有の文書表記を匿名化しました。157入力ファイルのうち133は元candidateとバイト一致し、24はこの匿名化による差分です。runtime Pythonはコメント・docstringを除くASTが一致し、テストの変更はfixture識別子に限られます。個別の元SHA・公開SHA・確認方法は `SOURCE_IMPORT.json` に記録しています。

元ZIPと公開ソースは異なるpackage identityです。元ZIPのSHA、当時のrelease metadata、正式リリース判断は変更していません。公開ソースには過去の実機ログ・調査結果・旧release manifestを含めず、取り込み時に過去のPASS記録を生成・転用していません。

ソース整合性はリポジトリrootから次で確認できます。

```bash
PYTHONDONTWRITEBYTECODE=1 python3 pipeline/package_integrity.py pipeline
```

開発依存はリポジトリrootの仮想環境へ導入してください。`pipeline/` 内に仮想環境や成果物を作ると、未登録ファイルとして整合性検査に失敗します。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r pipeline/requirements.lock
```

実データ専用の5テストは保持していますが、fixture本体は含めていません。実行には同じ公開用host/date/user識別子へ正規化した非公開fixtureが必要です。元の実データを無変換で指定して合格することは保証しません。通常の合成fixtureテストとは区別して扱います。

今回確認したのはファイル対応・AST・package integrityです。依存が不足する実行環境のため、既存focused 460件のPASSは再確認していません。`verify_release_package.py` は旧candidate一式の資料・実機証跡も検査するため、この公開ソース集合の検証には使いません。今後の配布・正式昇格には、その時点の実際の試験結果を用いたpackage作成が必要です。
