#!/usr/bin/env python3
"""Report likely identifiers and credentials before publishing a release.

This is deliberately report-only. The protected Run2 provenance files must be
byte-preserved, and blind text replacement can invalidate experimental code.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

TEXT_SUFFIXES = {".py", ".json", ".jsonl", ".md", ".txt", ".log"}
SKIP_PARTS = {".git", "__pycache__"}
PROTECTED_RUN2 = {
    Path("Run2_20260929/main/run_experiment.py"),
    Path("Run2_20260929/main/eval_dynamic.py"),
    Path("Run2_20260929/main/generation_logs/20260929_contract_repair_logged_manifest.json"),
}
RULES = {
    "email_address": re.compile(r"(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b"),
    "openai_style_key": re.compile(r"\\bsk-[A-Za-z0-9_-]{16,}\\b"),
    "github_token": re.compile(r"\\b(?:ghp|github_pat)_[A-Za-z0-9_]{16,}\\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "credential_assignment": re.compile(
        r"(?i)\\b(?:api[_-]?key|password|secret|access[_-]?token)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]"
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path, help="candidate release root")
    parser.add_argument("--report", type=Path, help="JSON report path (default: <root>/ANONYMIZATION_REPORT.json)")
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        print(f"[ERROR] Not a directory: {root}", file=sys.stderr)
        return 2
    findings: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(root)
        if any(part in SKIP_PARTS for part in relative.parts):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(lines, start=1):
            for name, pattern in RULES.items():
                if pattern.search(line):
                    findings.append({
                        "rule": name,
                        "path": str(relative),
                        "line": number,
                        "protected_run2_file": relative in PROTECTED_RUN2,
                    })
    report = args.report.resolve() if args.report else root / "ANONYMIZATION_REPORT.json"
    report.write_text(json.dumps({"findings": findings}, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {report}; findings: {len(findings)}")
    if findings:
        print("[REVIEW REQUIRED] Do not publish until every finding is resolved or documented.")
        return 1
    print("No matches for the configured credential/identifier patterns.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
