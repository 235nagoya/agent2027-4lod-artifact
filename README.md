# Reproducibility Package / 再現性パッケージ

This repository provides the experimental materials from
`Static_Dynamic_20260803`, `Run1_20260928`, and `Run2_20260929` for anonymous
peer review and reproducibility assessment. It does not publish operational
customer data.

本リポジトリは、匿名査読および再現性評価のために
`Static_Dynamic_20260803`、`Run1_20260928`、`Run2_20260929` の実験資料を提供します。
運用上の顧客データを公開するものではありません。

## Publication boundary / 公開範囲

The release includes reviewed source code, generated trial programs, evaluation
scripts, JSON results, and the Run2 generation record.

公開物には、レビュー済みのソースコード、生成試行プログラム、評価スクリプト、JSON結果、
およびRun2生成記録を含めます。

The following are excluded from publication:

- `customer_access_audit.log` (audit or operational traces)
- `dynamic_analysis/test_dummy.db` (database artifact containing test records)
- `__pycache__/` and `.DS_Store` (local build and OS artifacts)
- API keys, access tokens, credentials, real identifiers, and unreviewed logs

以下は公開対象外です。

- `customer_access_audit.log`（監査・運用トレース）
- `dynamic_analysis/test_dummy.db`（テストレコードを含むDB成果物）
- `__pycache__/` と `.DS_Store`（ローカル生成物・OS生成物）
- APIキー、アクセストークン、認証情報、実在識別子、未審査ログ

## Run2 integrity contract / Run2完全性契約

The following files are byte-preserved and must not be translated, reformatted,
anonymized, or otherwise edited:

- `Run2_20260929/main/run_experiment.py`
- `Run2_20260929/main/eval_dynamic.py`
- `Run2_20260929/main/generation_logs/20260929_contract_repair_logged_manifest.json`

The execution-contract text embedded in `run_experiment.py` is also fixed. The
manifest is the authoritative hash record; the supplied verification script also
pins the manifest itself.

上記のファイルおよび `run_experiment.py` に埋め込まれた実行契約本文は固定対象です。
翻訳・整形・匿名化その他の変更を行いません。マニフェストをハッシュ記録の正本とし、
検証スクリプトではマニフェスト自身も固定します。

The Japanese sources remain the canonical experimental artifacts. The bilingual
explanatory specification is supplementary and does not replace the
hash-protected Run2 files.

日本語ソースを正本の実験成果物として保持します。日英併記の説明仕様書は補足資料であり、
ハッシュ保護されたRun2ファイルを置換するものではありません。

## Reproducibility metadata / 再現性メタデータ

This release records the Python version, package versions, model identifier,
execution date, generation parameters, and API availability conditions required
to interpret and reproduce the experiment.

本リリースには、実験の解釈および再現に必要なPython版、パッケージ版、モデル識別子、
実行日、生成パラメータ、API利用条件を記録しています。

## Verify the archived Run2 artifact / 保存済みRun2の検証

Run the following command before analysis and after cloning a release:

```bash
python3 scripts/verify_run2_integrity.py --root .
```

Success means that the pinned Run2 manifest is unchanged and that its recorded
SHA-256 values match the release files. It does not establish that a model
provider will reproduce the same generations.

成功時は、固定したRun2マニフェストが未変更であり、記録されたSHA-256値がリリース内の
ファイルと一致したことを示します。モデルプロバイダが同一生成結果を再現することまでを
保証するものではありません。

## Build a reviewed public copy / 審査済み公開コピーの作成

```bash
python3 scripts/prepare_public_release.py \
  --source-root /path/to/experiments_parent \
  --output /path/to/public_release \
  --copy-kit .
python3 /path/to/public_release/scripts/verify_run2_integrity.py \
  --root /path/to/public_release
python3 /path/to/public_release/scripts/anonymize_for_release.py \
  --root /path/to/public_release
```

In the public copy only, the preparation script converts absolute JSONL
`final_file` paths to portable paths beginning `./generated_runs/`. The original
JSONL is never modified. Review `RELEASE_INVENTORY.json` and the anonymization
report before publication.

公開コピー内だけで、作成スクリプトはJSONLの絶対 `final_file` パスを
`./generated_runs/` から始まる移植可能なパスに変換します。元のJSONLは変更しません。
公開前に `RELEASE_INVENTORY.json` と匿名化報告を確認してください。

## Full computational rerun / 計算処理の完全再実行

Archived results can be re-evaluated locally with the included Python
evaluators. A new generation run is inherently non-deterministic and requires a
configured `OPENAI_API_KEY`, model access, and the model version recorded in the
Run2 manifest. Never commit credentials. Execute generated programs only in an
isolated environment.

保存済み結果は同梱のPython評価器でローカル再評価できます。新規生成の再実行は本質的に
非決定的であり、`OPENAI_API_KEY`、対象モデルへのアクセス、Run2マニフェストに記録された
モデル版が必要です。認証情報はコミットせず、生成プログラムは隔離環境でのみ実行してください。

## License and citation / ライセンスと引用

A license and formal citation information will be added after completion of the
double-blind review process. Until then, this repository is provided solely for
anonymous peer review and reproducibility assessment. Redistribution or reuse
is not permitted without prior permission from the authors.

ライセンスおよび正式な引用情報は、Double-Blind査読の完了後に追加します。それまで本
リポジトリは、匿名査読および再現性評価のみを目的として提供されます。著者の事前許可なく
再配布・再利用することはできません。

## Pre-publication checklist / 公開前チェックリスト

- [x] Run2 integrity verification passes.
- [x] Release inventory was manually reviewed.
- [x] No credentials, real personal data, or operational logs remain.
- [x] The Python version, package versions, model identifier, execution date,
      generation parameters, and API availability conditions are recorded.
- [x] Generated programs were executed only in an isolated environment.
- [x] License and formal citation are intentionally deferred until completion of
      double-blind review.

- [x] Run2完全性検証が成功した。
- [x] リリース目録を目視確認した。
- [x] 認証情報、実在個人情報、運用ログが残っていない。
- [x] Python版、パッケージ版、モデル識別子、実行日、生成パラメータ、API利用条件を記録した。
- [x] 生成プログラムは隔離環境でのみ実行した。
- [x] ライセンスおよび正式な引用情報はDouble-Blind査読終了後に追加する方針を明記した。
