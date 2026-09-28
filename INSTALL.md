# CheckPC v3.71 配置・更新入口

v3.71 の新規配置・既存版からの更新は、`docs/operations/CheckPC_汎用バージョンアップ手順書_v1.0.md` を基準とする。

## 必須原則

```text
現行版ディレクトリへ上書きしない
コードとEnvironmentFileを分離する
秘密値をrepository/packageへ入れない
新版検証は専用validation jobs領域で行う
stable symlinkはcode/envをセットで切り替える
comparison/release gateを旧版から流用しない
rollback先を確認してから切り替える
```

## 標準 stable link

```text
/opt/llm/analysis-current
/opt/llm/checkpc-pipeline-current.env
```

## v3.71について

正式版の基準 candidate は `v3.71-rc16`。

candidate 内の `RELEASE_STATUS=validation-pending` は候補固定時点の値であり、候補 artifact の SHA と監査証跡を維持するため GitHub 整理時には書き換えない。正式リリース状態は `docs/releases/v3.71/RELEASE_NOTES.md` を参照する。

環境固有の URL、秘密値、認証 hash、VT API key、proxy credential はこの repository へ記録しない。
