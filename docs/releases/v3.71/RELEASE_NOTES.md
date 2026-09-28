# CheckPC v3.71 正式リリース記録

正式リリース日: 2026-09-28  
基準 candidate: v3.71-rc16  
candidate 固定日: 2026-08-24  
判定: **v3.71 正式リリース完了**

## 1. 正式版の位置付け

v3.71 は v3.70 rev14-formal の解析 core を基準に、解析結果 chat の Threat Intelligence 機能を重点的に再設計したリリースである。

GitHub 整理では rc16 candidate の runtime code に機能変更を加えず、候補時点の SHA / manifest / validation metadata を監査証跡として保持する。

## 2. rc16 で解消した blocker

### 英語

否定文中の bare comma を肯定 directive の境界と誤認し、否定対象 IOC を authorize する問題を修正。

例:

```text
do not, under any circumstances, check 8.8.8.8 with VirusTotal
never, ever, check 8.8.8.8
please do not, for any reason, check 8.8.8.8
```

期待:

```text
authorized IOC set = empty
forced vt_ioc_lookup(8.8.8.8) external transport = 0
```

### 日本語

「確認」「検索」「調査」等の肯定 action 部分だけを拾い、後続否定を無視する問題を修正。

例:

```text
8.8.8.8をVTで確認するのはやめて
8.8.8.8を検索するのはやめて
8.8.8.8を調べてほしくない
8.8.8.8を確認してほしくない
```

期待:

```text
authorized IOC set = empty
forced vt_ioc_lookup(8.8.8.8) external transport = 0
```

## 3. candidate focused regression

```text
test_chat_tools.py                  48 PASS
test_v371_chat_ti_redesign.py      252 PASS
test_server_chat_integration.py     39 PASS
test_v370_directory_evidence.py     71 PASS
test_v370_directory_scoped_chat.py  50 PASS
--------------------------------------------
TOTAL                              460 PASS
FAIL                                 0
```

GitHub 取り込み前にも、clean extraction で package manifest と上記 focused tests を再実行し、460 / 460 PASS を確認した。

## 4. 独立ダブルチェックで確認した点

- 英語否定 3ケースで authorized set が空。
- 日本語否定 7ケースで authorized set が空。
- forced `vt_ioc_lookup(8.8.8.8)` でも external transport は 0。
- mixed directive では明示肯定された IOC だけを route。
- rc15 で失敗していた追加 fixture は rc16 で PASS。
- P0 / P1 の新規 blocker は確認されなかった。
- 解析 core は rc15 から変更対象外。

## 5. candidate metadata の扱い

rc16 package は正式昇格前に固定されたため、内部の `version.py`、`release_manifest.json`、検証資料には `validation-pending` が残る。

この値を GitHub 取り込み時に `release` へ書き換えると、candidate の package SHA / manifest / 独立監査対象が変わるため、改変しない。

正式リリース判断は本ファイルで記録し、candidate artifact と release decision を分離する。

## 6. 証跡上の注意

今回参照した v3.71-rc16 candidate 配布物には、candidate 固定後に実施する base117 上の fresh formal 4mode / comparison / release-mode / cutover 証跡そのものは含まれていない。

そのため、この repository 整理では存在しない `formal_promotion.json` 等を生成して補完しない。正式リリース決定と candidate package の検証証跡を明確に分ける。
