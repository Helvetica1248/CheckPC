# CheckPC APT Analysis Pipeline v3.71

CheckPC が収集した Windows 初動調査データ（CAB/TXT）を、ローカル LLM と決定論的ルールで解析し、ホスト単位のレポート、横断相関、タイムライン、解析結果チャットを生成するパイプラインです。

**v3.71 は 2026-09-28 に正式リリース完了としました。** 実装系譜は `v3.70 rev14-formal` → `v3.71-rc1 ... rc16` で、正式版は最終候補 `v3.71-rc16` を基準にしています。

## リポジトリ構成

- `DESIGN.md` — v3.71の現行設計と安全境界
- `CHANGELOG.md` — v3.71正式化と主要変更履歴
- `docs/releases/v3.71/RELEASE_NOTES.md` — 正式リリース記録
- `docs/operations/CheckPC_汎用バージョンアップ手順書_v1.0.md` — stable symlink方式の更新手順
- `docs/operations/GUI_USER_GUIDE.md` — GUI利用ガイド
- `artifacts/checkpc_v3.71_source.tar.xz` — v3.71-rc16候補一式を原形保存したsource bundle

## v3.71の主要変更

v3.71では解析本体よりも、解析結果チャットのThreat Intelligence境界を重点的に再設計しました。

- LLM公開toolを `investigate_local` と `vt_ioc_lookup` に集約
- 案件scope、mixed-version normalization、coverage、distinct-host prevalenceをPython側で決定
- raw Directory等の巨大証拠をbounded search / SQLite indexで扱い、初回チャットで案件全台を同期index化しない
- VirusTotal等の外部TI送信は、current turnで明示肯定されたIOCだけをauthorize
- 否定文、混在directive、複数IOC、英語comma境界、日本語「～するのはやめて」「～してほしくない」等をfail-closed化
- parser / analyze / correlate / Depth1/2 / comparison / provenanceはv3.70 rev14-formalを基準に維持

## 正式版とrc16 candidateについて

source bundleは、正式昇格前に固定したcandidate packageの**原形保存**です。そのため内部の `version.py` / `release_manifest.json` / `TEST_RESULTS.md` には当時の `validation-pending` が残っています。GitHub取り込み時にこれらを改変するとcandidate packageのSHA・manifest・監査証跡を壊すため、書き換えていません。

正式リリース状態とcandidate snapshotの関係は `docs/releases/v3.71/RELEASE_NOTES.md` に記録しています。

## セキュリティ方針

- 取りこぼし防止を優先し、LLMだけで最終判定しない
- 証拠、追加context、tool resultは非信頼入力として境界化
- 外部TI送信は明示許可されたIOCだけを対象とし、曖昧な自然言語はfail-closed
- 秘密値・認証情報・TLS鍵・VT API key・proxy認証情報はパッケージ外のEnvironmentFileで管理
- 正式更新はコードとEnvironmentFileをstable symlinkでセット切替し、rollback可能性を維持

詳細は `DESIGN.md` と汎用バージョンアップ手順書を参照してください。
