#!/usr/bin/env python3
"""Create a conservative, reviewable public copy of the three experiment folders.

This tool never edits the source folders. It excludes operational/log/database/cache
artifacts and preserves protected Run2 provenance inputs byte-for-byte.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

FOLDERS = ("Static_Dynamic_20260803", "Run1_20260928", "Run2_20260929")
ALLOWED_SUFFIXES = {".py", ".json", ".jsonl", ".md", ".txt"}
EXCLUDED_NAMES = {".DS_Store", "customer_access_audit.log", "test_dummy.db"}
EXCLUDED_PARTS = {"__pycache__"}
PROTECTED_RUN2 = {
    Path("Run2_20260929/main/run_experiment.py"),
    Path("Run2_20260929/main/eval_dynamic.py"),
    Path("Run2_20260929/main/generation_logs/20260929_contract_repair_logged_manifest.json"),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def is_excluded(relative: Path) -> bool:
    return relative.name in EXCLUDED_NAMES or any(part in EXCLUDED_PARTS for part in relative.parts)


def anonymize_jsonl_final_file(source: Path, destination: Path) -> int:
    """Copy JSONL while replacing an absolute generated_runs final_file path.

    The original JSONL remains untouched.  Only the release copy is changed;
    the Run2 integrity contract does not include this JSONL file.
    """
    rewritten = 0
    output_lines: list[str] = []
    for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            output_lines.append(line)
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSONL at {source}:{line_number}: {exc}") from exc
        final_file = record.get("final_file")
        if isinstance(final_file, str) and Path(final_file).is_absolute():
            parts = Path(final_file).parts
            if "generated_runs" not in parts:
                raise ValueError(
                    f"Absolute final_file does not contain generated_runs at {source}:{line_number}"
                )
            start = parts.index("generated_runs")
            record["final_file"] = "./" + "/".join(parts[start:])
            rewritten += 1
        output_lines.append(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
    destination.write_text("\n".join(output_lines) + "\n", encoding="utf-8")
    return rewritten


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path, help="parent containing the three input folders")
    parser.add_argument("--output", required=True, type=Path, help="new, empty output directory")
    parser.add_argument("--copy-kit", type=Path, help="directory containing README.md, docs/, and scripts/")
    args = parser.parse_args()
    source = args.source_root.resolve()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        print("[ERROR] --output must be a new or empty directory.", file=sys.stderr)
        return 2
    missing = [name for name in FOLDERS if not (source / name).is_dir()]
    if missing:
        print("[ERROR] Missing input folder(s): " + ", ".join(missing), file=sys.stderr)
        return 2
    output.mkdir(parents=True, exist_ok=True)
    inventory: list[dict[str, str]] = []
    excluded: list[str] = []
    path_rewrites: list[dict[str, object]] = []
    for folder in FOLDERS:
        for path in sorted((source / folder).rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(source)
            if is_excluded(relative) or path.suffix.lower() not in ALLOWED_SUFFIXES:
                excluded.append(str(relative))
                continue
            destination = output / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if path.suffix.lower() == ".jsonl":
                rewritten = anonymize_jsonl_final_file(path, destination)
                if rewritten:
                    path_rewrites.append({"path": str(relative), "final_file_rewrites": rewritten})
            else:
                shutil.copyfile(path, destination)
            if relative in PROTECTED_RUN2 and sha256(path) != sha256(destination):
                print(f"[ERROR] Protected file changed while copying: {relative}", file=sys.stderr)
                return 1
            inventory.append({"path": str(relative), "sha256": sha256(destination)})
    if args.copy_kit:
        kit = args.copy_kit.resolve()
        for item in ("README.md", "docs", "scripts"):
            origin = kit / item
            if not origin.exists():
                print(f"[ERROR] Publication-kit item is missing: {origin}", file=sys.stderr)
                return 2
            destination = output / item
            if origin.is_dir():
                shutil.copytree(origin, destination, dirs_exist_ok=True)
            else:
                shutil.copyfile(origin, destination)
    (output / "RELEASE_INVENTORY.json").write_text(
        json.dumps(
            {
                "included": inventory,
                "excluded": excluded,
                "anonymized_final_file_paths": path_rewrites,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        f"Prepared {len(inventory)} files. Excluded {len(excluded)} files. "
        f"Rewrote {sum(item['final_file_rewrites'] for item in path_rewrites)} JSONL path(s)."
    )
    print("Review RELEASE_INVENTORY.json and run verify_run2_integrity.py before publication.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
