#!/usr/bin/env python3
"""Verify the immutable Run2 provenance record without modifying any data."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys

MANIFEST_RELATIVE = Path("Run2_20260929/main/generation_logs/20260929_contract_repair_logged_manifest.json")
RUN_EXPERIMENT_RELATIVE = Path("Run2_20260929/main/run_experiment.py")
EVAL_DYNAMIC_RELATIVE = Path("Run2_20260929/main/eval_dynamic.py")
# SHA-256 of the original Run2 manifest. Update only when intentionally creating
# a new provenance version; never replace the original manifest in place.
PINNED_MANIFEST_SHA256 = "92b1c68ba6bef11c3c475ba2f52ee82beb94a420b5886429aa1ccbc81c849844"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def execution_contract(path: Path) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "EXECUTION_CONTRACT"
            for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if isinstance(value, str):
                return value
    raise ValueError("EXECUTION_CONTRACT string assignment was not found")


def check(label: str, actual: str, expected: str) -> bool:
    status = "OK" if actual == expected else "MISMATCH"
    print(f"[{status}] {label}: {actual}")
    return actual == expected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository root")
    args = parser.parse_args()
    root = args.root.resolve()
    manifest_path = root / MANIFEST_RELATIVE
    run_path = root / RUN_EXPERIMENT_RELATIVE
    eval_path = root / EVAL_DYNAMIC_RELATIVE

    missing = [str(path.relative_to(root)) for path in (manifest_path, run_path, eval_path) if not path.is_file()]
    if missing:
        print("[ERROR] Missing required file(s): " + ", ".join(missing), file=sys.stderr)
        return 2

    manifest_hash = sha256_file(manifest_path)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[ERROR] Invalid manifest JSON: {exc}", file=sys.stderr)
        return 2

    required = {"run_experiment_sha256", "eval_dynamic_sha256", "execution_contract_sha256"}
    if not required.issubset(manifest):
        print("[ERROR] Manifest lacks one or more required SHA-256 fields.", file=sys.stderr)
        return 2

    results = [
        check("manifest", manifest_hash, PINNED_MANIFEST_SHA256),
        check("run_experiment.py", sha256_file(run_path), manifest["run_experiment_sha256"]),
        check("eval_dynamic.py", sha256_file(eval_path), manifest["eval_dynamic_sha256"]),
        check(
            "embedded EXECUTION_CONTRACT",
            hashlib.sha256(execution_contract(run_path).encode("utf-8")).hexdigest(),
            manifest["execution_contract_sha256"],
        ),
    ]
    if all(results):
        print("Run2 integrity verification PASSED.")
        return 0
    print("Run2 integrity verification FAILED.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
