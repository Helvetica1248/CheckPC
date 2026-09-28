# CheckPC 解析パイプライン GUI 操作ガイド（v3.71）

この画面は、CheckPC で収集した CAB または TXT をローカル解析サーバーへ投入し、端末ごとの感染トリアージ結果を作成・確認するための画面です。

> 本システムは初動調査を支援するもので、感染の有無を自動的に確定するものではありません。HIGH / MEDIUM だけでなく、収集品質、fallback、解析制限、raw evidence を確認し、必要に応じて追加調査してください。

> `directory個別評価カバレッジ` 警告が出た場合、未個別評価の証拠が存在します。レポート記載分だけで不存在を断定せず、Chat の案件内 raw 検索を使用してください。

## 1. クイックスタート

1. 「CAB / TXTをここにドロップ」へ CheckPC 成果物を投入します。
2. 通常は **Depth 1 / LEAN** を選びます。
3. 同じ案件の端末には同じ「フォルダ」名を付けます。
4. 必要な場合だけ追加 context と VirusTotal API key を入力します。
5. 「解析開始」を押します。複数ファイルは 1ファイル 1ジョブで登録されます。
6. 完了後、標準レポート、タイムライン、PDF、収集品質警告を確認します。
7. 必要な端末だけ Depth 2 / FULL で再調査します。

## 2. 入力と外部 TI

- 対応入力は CheckPC が生成した CAB / TXT。
- サーバー認証情報と VirusTotal API key は別物です。
- 通常解析はローカル LLM で完結します。
- VirusTotal へ送信できるのは、current turn で利用者が明示的に照会を肯定した IOC のみです。
- URL、ファイルパス、ファイル名、private / reserved IP、検体本体、モデルが新規生成した未根拠 IOC は送信対象にしません。
- 外部 TI を利用しない案件では VT key を設定せず、Chat の外部照会を使用しません。

## 3. Depth と FULL / LEAN

### Depth 1

通常運用の標準。高優先度証拠を中心に評価します。

### Depth 2

再調査・詳細確認向け。より広い証拠を扱うため、Depth 1 より処理時間と中間成果物が増えます。

### LEAN

根拠と主要 IOC を維持しつつ説明量を抑える通常推奨モードです。

### FULL

より詳細な説明を生成します。LEAN より出力量・処理時間が増えます。

## 4. ジョブ状態

```text
待機
解析中
完了
エラー
中断済み
```

中断は安全な中断点で反映されるため、実行中 LLM call の終了まで時間を要する場合があります。

## 5. 主な成果物

- 標準レポート: HIGH / MEDIUM 中心
- 全件版: LOW を含む詳細
- PDF
- タイムライン / タイムライン PDF
- Defender 集約
- Markdown
- JSON
- validation ZIP
- full ZIP

### validation ZIP

日常レビュー、版間比較、共有向け。主に analyzed、correlation、ingest manifest、job log、report 等を含みます。

### full ZIP

output 配下の全 regular file を対象とし、parsed を含む完全 provenance 確認向けです。

ZIP 生成は archive worker へ分離され、同じ job の有効な既存 ZIP は再利用されます。

## 6. 警告と fallback

次は「問題なし」と同義ではありません。

- 横断相関出力の制限
- 横断相関 fallback
- 横断相関 metadata 不整合
- 収集品質低下
- 未評価証拠
- Directory 個別評価 coverage 不足

fallback や coverage 警告がある場合は、元証拠・raw search・必要に応じた再解析で確認してください。

## 7. Chat

v3.71 の Chat は、案件内調査と任意の外部 TI 照会を分離します。

```text
investigate_local
  案件内の証拠検索・横断確認

vt_ioc_lookup
  明示的に許可されたIOCだけを外部TI照会
```

### 案件内検索

同じ案件 scope の複数ホストを横断して、hash、IP、domain、path、filename、raw Directory 等を検索できます。

### 外部照会

「VTで確認して」等、current turn で明示肯定された対象だけが authorize されます。

次のような否定は authorize されません。

```text
8.8.8.8をVTで確認するのはやめて
8.8.8.8を調べてほしくない
do not, under any circumstances, check 8.8.8.8 with VirusTotal
```

混在 directive の場合も、肯定対象と否定対象を IOC 単位で分離します。曖昧な場合は fail-closed です。

## 8. フォルダ・削除

フォルダは案件整理と Chat の scope 境界に使います。解析中は中断後、ZIP 作成中は生成終了後に削除してください。

削除対象には入力、中間データ、解析結果、監査 fallback、生成 ZIP が含まれるため、必要な証跡を保存してから実行します。

## 9. 標準運用フロー

```text
1. Depth 1 / LEAN
2. HIGH / MEDIUM + timeline + collection quality + warnings
3. 必要端末だけ Depth 2 / FULL
4. Chatで案件内証拠を横断
5. 必要時のみ明示的に外部TI照会
6. validation ZIP / full ZIP を用途別に保存
7. 案件ルールに従ってjobを削除
```

## 10. 用語

- **provenance**: 判定を元収集エントリへ結び付ける監査情報。
- **deterministic fallback**: LLM を利用できない場合にルール側で最低限の結果を構成する処理。
- **source_id**: 元証拠を安定して識別する ID。
- **validation ZIP**: 日常レビュー・比較向け。
- **full ZIP**: parsed を含む完全成果物向け。
