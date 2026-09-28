# Changelog

## v3.71 — 2026-09-28 — Formal release

- 最終 candidate `v3.71-rc16` を基準に v3.71 正式リリース完了。
- 解析 core は v3.70 rev14-formal を基準に維持。
- Chat Threat Intelligence を再設計し、案件 scope、coverage、host prevalence、Directory bounded search、外部 TI authorization を Python 側へ寄せた。
- 外部 TI 送信は current turn で明示肯定された IOC のみに限定。
- rc16 で次の authorization blocker を修正。
  - 英語否定文中の bare comma を肯定 directive 境界と誤認する問題。
  - 日本語の「～するのはやめて」「～してほしくない」等で肯定 action 部分だけが一致する問題。
- rc16 candidate focused regression:
  - `test_chat_tools.py`: 48 PASS
  - `test_v371_chat_ti_redesign.py`: 252 PASS
  - `test_server_chat_integration.py`: 39 PASS
  - `test_v370_directory_evidence.py`: 71 PASS
  - `test_v370_directory_scoped_chat.py`: 50 PASS
  - 合計 460 PASS / 0 FAIL
- 独立ダブルチェックでは、対象否定文の authorized set が空、forced `vt_ioc_lookup(8.8.8.8)` の external transport が 0、mixed positive routing が維持されることを確認。
- GitHub 取り込み前に candidate package manifest と focused 460 tests を再確認し PASS。
- candidate snapshot 内の `validation-pending` は candidate 固定時点の監査 metadata として保持し、正式化のために改変しない。

## v3.71-rc16 — 2026-08-24

- rc15 独立監査で確認された VT authorization P0 2系統を限定修正。
- 主変更: `chat_tools.py`
- 既存 mixed positive routing を維持。
- candidate focused regression 460 / 460 PASS。
- この時点では formal release ではなく `validation-pending`。

## v3.71-rc1 ... rc15

v3.71 系列では主として Chat Threat Intelligence の scope、Evidence Pivot、Directory evidence、prevalence、timeline、外部 TI authorization の安全境界を段階的に修正した。

個々の candidate-era 詳細は、v3.71 配布物の README / DESIGN / CHANGELOG / 検証記録を一次資料とする。

## v3.70 rev14-formal

v3.71 の解析 core baseline。Depth1 / Depth2 比較修正版として正式昇格済み。
