# Reproducibility package / 再現性パッケージ

This repository publishes the experimental materials from `Static_Dynamic_20260803`,
`Run1_20260928`, and `Run2_20260929`. It is intended to make the reported
analyses inspectable and reproducible, not to publish operational customer data.

このリポジトリは、`Static_Dynamic_20260803`、`Run1_20260928`、
`Run2_20260929` の実験資料を公開するためのものです。報告した分析を検証・
再現できるようにすることを目的とし、運用上の顧客データを公開するものではありません。

## Publication boundary / 公開範囲

Publish source code, generated trial programs, evaluation scripts, JSON results,
and the Run2 generation record when they have passed the release review.

公開するのは、リリース審査を通過したソースコード、生成試行プログラム、評価スクリプト、
JSON結果、Run2の生成記録です。

Do **not** publish these files:

- `customer_access_audit.log` (audit/operational trace)
- `dynamic_analysis/test_dummy.db` (database artifact containing test records)
- `__pycache__/` and `.DS_Store` (local build or OS artifacts)
- API keys, access tokens, credentials, real identifiers, or unreviewed logs

次のファイルは**公開しません**。

- `customer_access_audit.log`（監査・運用トレース）
- `dynamic_analysis/test_dummy.db`（テストレコードを含むDB成果物）
- `__pycache__/` と `.DS_Store`（ローカル生成物・OS生成物）
- APIキー、アクセストークン、認証情報、実在識別子、未審査ログ

## Run2 integrity contract / Run2完全性契約

The following Run2 files are byte-preserved. Do not translate, reformat,
anonymize, or otherwise edit them:

- `Run2_20260929/main/run_experiment.py`
- `Run2_20260929/main/eval_dynamic.py`
- `Run2_20260929/main/generation_logs/20260929_contract_repair_logged_manifest.json`

The execution-contract text embedded in `run_experiment.py` is also fixed. The
manifest is the authoritative record of the hashes for the two files and that
embedded text. The manifest itself is pinned by this kit.

上記のRun2ファイルはバイト単位で保存します。翻訳、整形、匿名化、その他の編集は
行いません。`run_experiment.py` 内の実行契約本文も固定対象です。2ファイルと実行契約
本文のハッシュはマニフェストを正とし、マニフェスト自身のハッシュは本キットで固定します。

The Japanese source remains the canonical experimental artifact. An English
translation and a Japanese original are presented side by side in
[`docs/EXPERIMENT_SPECIFICATION.md`](docs/EXPERIMENT_SPECIFICATION.md); that
document is explanatory and is not a replacement for, or a translation of, the
hash-protected Run2 files.

日本語ソースは正本の実験成果物として保持します。英訳と日本語原文は
[`docs/EXPERIMENT_SPECIFICATION.md`](docs/EXPERIMENT_SPECIFICATION.md) に併記します。
これは説明資料であり、ハッシュ保護されたRun2ファイルの置換や翻訳ではありません。

## Repository layout / リポジトリ構成

```text
.
├── Run1_20260928/
├── Run2_20260929/
├── Static_Dynamic_20260803/
├── docs/
└── scripts/
```

## Verify the archived Run2 artifact / 保存済みRun2の検証

Run this before analysis and after cloning a release:

```bash
python3 scripts/verify_run2_integrity.py --root .
```

Success means that the pinned Run2 manifest is unchanged and that its three
recorded SHA-256 values match the release files. It does not establish that a
model provider will reproduce the same generations.

成功時は、固定したRun2マニフェストが未変更であり、そこに記録された3つのSHA-256値が
リリース内のファイルと一致したことを示します。モデルプロバイダが同一の生成結果を再現
することまで保証するものではありません。

## Build a reviewed public copy / 審査済み公開コピーの作成

Place the three supplied folders in one input directory, then run:

```bash
python3 scripts/prepare_public_release.py \
  --source-root /path/to/input \
  --output /path/to/release \
  --copy-kit .
python3 /path/to/release/scripts/verify_run2_integrity.py --root /path/to/release
```

The script copies only reviewable text and result formats, omits the excluded
artifacts above, and stops if it would change any protected Run2 file. In the
**public copy only**, it converts an absolute JSONL `final_file` path to a
portable path beginning `./generated_runs/`; the original JSONL is never
modified. Review the generated `RELEASE_INVENTORY.json` and the scanner report
before publishing.

このスクリプトは審査可能なテキスト・結果形式だけをコピーし、除外対象を省きます。保護された
Run2ファイルを変更しようとする場合は停止します。**公開コピー内だけで**、JSONLの絶対
`final_file` パスを `./generated_runs/` から始まる移植可能なパスへ変更します。元のJSONLは
変更しません。公開前に生成された
`RELEASE_INVENTORY.json` とスキャナ報告を必ず確認してください。

Scan a candidate for common credentials and direct identifiers with:

```bash
python3 scripts/anonymize_for_release.py --root /path/to/release
```

The scanner intentionally reports rather than silently rewriting material.
Automatic redaction could invalidate research code, and it is prohibited for
the hash-protected Run2 files. Resolve every finding by removal, an explicitly
reviewed synthetic substitute, or a documented false-positive decision.

候補を一般的な認証情報・直接識別子について走査するには、次を実行します。
このスキャナは無断で書き換えず、検出結果を報告します。自動置換は研究コードを壊し得るうえ、
ハッシュ保護されたRun2ファイルには禁止されています。検出結果は削除、明示的にレビューした
合成置換、または根拠を記録した誤検出判定のいずれかで必ず解消してください。

## Full computational rerun / 計算処理の完全再実行

The archived results can be re-evaluated locally with the included Python
evaluators. A new generation run is inherently non-deterministic and requires a
configured `OPENAI_API_KEY`, model access, and the model version recorded in the
Run2 manifest. Never commit credentials. Re-run generated programs only in an
isolated environment because they are model-produced code.

保存済み結果は同梱のPython評価器でローカル再評価できます。新規生成の再実行は本質的に
非決定的であり、`OPENAI_API_KEY`、対象モデルへのアクセス、Run2マニフェストに記録された
モデル版が必要です。認証情報は絶対にコミットしないでください。生成プログラムはモデル生成
コードのため、必ず隔離環境で実行してください。

## Pre-publication checklist / 公開前チェックリスト

- [ ] Run2 integrity verification passes.
- [ ] Release inventory was manually reviewed.
- [ ] No credentials, real personal data, or operational logs remain.
- [ ] The license, citation, Python version, package versions, model identifier,
      date, temperature/other generation parameters, and API availability are documented.
- [ ] Generated programs were executed only in an isolated environment.

- [ ] Run2完全性検証が成功した。
- [ ] リリース目録を目視確認した。
- [ ] 認証情報、実在個人情報、運用ログが残っていない。
- [ ] ライセンス、引用方法、Python版、パッケージ版、モデル識別子、実行日、温度等の生成
      パラメータ、API利用可否を記録した。
- [ ] 生成プログラムは隔離環境でのみ実行した。
