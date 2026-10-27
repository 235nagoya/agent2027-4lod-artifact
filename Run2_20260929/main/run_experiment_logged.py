"""Generate 120 contract-and-repair samples while preserving every attempt."""

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

from openai import OpenAI

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import eval_dynamic
from run_experiment import (
    BASE_CONDITIONS,
    EXECUTION_CONTRACT,
    MAX_EXECUTION_REPAIRS,
    MODEL,
    NUM_TRIALS,
    clean_code,
)

RUN_ID = "20260929_contract_repair_logged"
RUN_GENERATED_DIR = os.path.join(BASE_DIR, "generated_runs", RUN_ID)
LOG_DIR = os.path.join(BASE_DIR, "generation_logs")
TRIAL_LOG_PATH = os.path.join(LOG_DIR, f"{RUN_ID}.jsonl")
MANIFEST_PATH = os.path.join(LOG_DIR, f"{RUN_ID}_manifest.json")

# Only the four integrated pipeline conditions are regenerated for Table 2.
RUN_CONDITIONS = {
    f"{name}_contract": f"{prompt.rstrip()}\n\n{EXECUTION_CONTRACT}"
    for name, prompt in BASE_CONDITIONS.items()
}
client = OpenAI()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: str) -> str:
    with open(path, "rb") as source_file:
        return hashlib.sha256(source_file.read()).hexdigest()


def sanitize_error_message(message: str | None) -> str | None:
    if message is None:
        return None
    for value in eval_dynamic.SENSITIVE_VALUES:
        message = message.replace(value, "[REDACTED]")
    return message


def write_jsonl(record: dict) -> None:
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(TRIAL_LOG_PATH, "a", encoding="utf-8") as log_file:
        json.dump(record, log_file, ensure_ascii=False)
        log_file.write("\n")


def save_candidate(attempt_dir: str, trial: int, attempt: int, code: str) -> str:
    os.makedirs(attempt_dir, exist_ok=True)
    path = os.path.join(attempt_dir, f"run_{trial}_attempt_{attempt}.py")
    with open(path, "w", encoding="utf-8") as candidate_file:
        candidate_file.write(code)
    return path


def evaluate_candidate(path: str, code: str) -> dict:
    # Recreate the database before each candidate to prevent state leakage.
    eval_dynamic.create_master_dummy_db()
    return eval_dynamic.evaluate_code_dynamically(path, code)


def attempt_record(attempt: int, is_repair: bool, code: str, result: dict) -> dict:
    return {
        "attempt": attempt,
        "is_repair": is_repair,
        "code_sha256": sha256_text(code),
        "outcome": result["outcome"],
        "execution_error": result["execution_error"],
        "error_type": result["error_type"],
        "error_message": sanitize_error_message(result["error_message"]),
    }


def request_code(prompt: str) -> str:
    response = client.chat.completions.create(
        model=MODEL, messages=[{"role": "user", "content": prompt}]
    )
    return clean_code(response.choices[0].message.content)


def repair_prompt(base_name: str, code: str, result: dict, repair_number: int) -> str:
    return f"""Repair the complete Python implementation below.

Original task:
{BASE_CONDITIONS[base_name]}

Execution contract:
{EXECUTION_CONTRACT}

Observed execution error (repair {repair_number}/{MAX_EXECUTION_REPAIRS}):
{result['error_type']}: {sanitize_error_message(result['error_message'])}

Return the complete corrected Python code only.

Current code:
```python
{code}
```
"""


def write_manifest() -> None:
    os.makedirs(LOG_DIR, exist_ok=True)
    manifest = {
        "run_id": RUN_ID,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "model": MODEL,
        "num_trials_per_condition": NUM_TRIALS,
        "max_execution_repairs": MAX_EXECUTION_REPAIRS,
        "conditions": list(RUN_CONDITIONS),
        "run_experiment_sha256": sha256_file(os.path.join(BASE_DIR, "run_experiment.py")),
        "eval_dynamic_sha256": sha256_file(os.path.join(BASE_DIR, "eval_dynamic.py")),
        "execution_contract_sha256": sha256_text(EXECUTION_CONTRACT),
    }
    with open(MANIFEST_PATH, "w", encoding="utf-8") as manifest_file:
        json.dump(manifest, manifest_file, indent=2, ensure_ascii=False)


def run_experiment() -> None:
    if os.path.exists(TRIAL_LOG_PATH):
        raise FileExistsError(
            f"Existing log: {TRIAL_LOG_PATH}. Change RUN_ID for a new experiment."
        )
    write_manifest()
    print(f"=== Logged contract-and-repair experiment: {len(RUN_CONDITIONS) * NUM_TRIALS} trials ===")

    for condition_name, initial_prompt in RUN_CONDITIONS.items():
        base_name = condition_name.removesuffix("_contract")
        condition_dir = os.path.join(RUN_GENERATED_DIR, condition_name)
        attempt_dir = os.path.join(condition_dir, "attempts")
        os.makedirs(condition_dir, exist_ok=True)
        print(f"\n>>> {condition_name}: {NUM_TRIALS} trials")

        for trial in range(1, NUM_TRIALS + 1):
            final_path = os.path.join(condition_dir, f"run_{trial}.py")
            if os.path.exists(final_path):
                raise FileExistsError(f"Final code already exists: {final_path}")

            code = None
            api_error = None
            for api_attempt in range(1, 4):
                try:
                    code = request_code(initial_prompt)
                    break
                except Exception as exc:
                    api_error = f"{type(exc).__name__}: {exc}"
                    print(f"  [{trial}/{NUM_TRIALS}] API retry {api_attempt}/3: {api_error}")
                    time.sleep(2)
            if code is None:
                write_jsonl({
                    "run_id": RUN_ID,
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                    "condition": condition_name,
                    "trial": trial,
                    "generation_status": "api_failed",
                    "api_error": api_error,
                })
                continue

            attempts = []
            initial_path = save_candidate(attempt_dir, trial, 0, code)
            initial_result = evaluate_candidate(initial_path, code)
            attempts.append(attempt_record(0, False, code, initial_result))

            result = initial_result
            repair_count = 0
            while result["execution_error"] and repair_count < MAX_EXECUTION_REPAIRS:
                repair_count += 1
                code = request_code(repair_prompt(base_name, code, result, repair_count))
                repaired_path = save_candidate(attempt_dir, trial, repair_count, code)
                result = evaluate_candidate(repaired_path, code)
                attempts.append(attempt_record(repair_count, True, code, result))

            with open(final_path, "w", encoding="utf-8") as final_file:
                final_file.write(code)

            write_jsonl({
                "run_id": RUN_ID,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "condition": condition_name,
                "trial": trial,
                "generation_status": "completed",
                "model": MODEL,
                "initial_outcome": initial_result["outcome"],
                "initial_execution_error": initial_result["execution_error"],
                "repair_count": repair_count,
                "attempt_outcomes": attempts,
                "final_outcome": result["outcome"],
                "final_execution_error": result["execution_error"],
                "final_code_sha256": sha256_text(code),
                "final_file": final_path,
            })
            print(f"  [{trial}/{NUM_TRIALS}] initial={initial_result['outcome']} repairs={repair_count} final={result['outcome']}")
            time.sleep(0.5)

    print(f"\nLog: {TRIAL_LOG_PATH}")
    print(f"Generated code: {RUN_GENERATED_DIR}")


if __name__ == "__main__":
    run_experiment()
