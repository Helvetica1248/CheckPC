# v3.71 source delta overview

比較基準: `v3.70 rev14-formal`  
正式版基準 candidate: `v3.71-rc16`

v3.71 の中心は chat / Threat Intelligence 境界である。解析 core を全面改変したリリースではない。

## 主要 runtime change

```text
CHG chat_tools.py
CHG checkpc-pipeline.env.example
CHG directory_index.py
CHG runtime_identity.py
CHG server.py
CHG version.py
ADD chat_investigation.py
```

## 主要 test change

```text
CHG test_chat_tools.py
CHG test_server_chat_integration.py
CHG test_v370_directory_evidence.py
CHG test_v370_directory_scoped_chat.py
ADD test_v371_chat_ti_redesign.py
```

rc16 の限定修正対象は主として `chat_tools.py` であり、英語 comma 境界と日本語否定 directive の外部 TI authorization を修正した。

## Artifact integrity

candidate distribution SHA-256 は `CANDIDATE_SHA256.txt` に記録する。候補 package 内の manifest / release metadata は、正式化を理由に後編集しない。
