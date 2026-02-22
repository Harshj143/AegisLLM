#!/usr/bin/env python3
"""
Web frontend bridge for the LLM Safety Automation Toolkit.
Serves the HTML dashboard and exposes API endpoints that run the existing scripts.
"""

from __future__ import annotations

import csv
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory


BASE_DIR = Path(__file__).parent
SCRIPTS_DIR = BASE_DIR / "scripts"
DEFAULT_URL = "http://localhost:5000/api/chat"
DEFAULT_JUDGE_URL = os.getenv("JUDGE_API_URL", "https://api.openai.com/v1/chat/completions")
DEFAULT_JUDGE_MODEL = os.getenv("JUDGE_MODEL_NAME", "gpt-4o")

OWASP_TESTS = [
    {
        "id": "LLM01",
        "name": "Prompt Injection",
        "icon": "💉",
        "description": "Test for malicious prompt manipulation and system instruction override",
        "folders": ["prompts", "jailbreaks"],
    },
    {
        "id": "LLM02",
        "name": "Sensitive Information Disclosure",
        "icon": "🔐",
        "description": "Detect unauthorized exposure of secrets, credentials, and API keys",
        "folders": ["Sensitivedata"],
    },
    {
        "id": "LLM05",
        "name": "Improper Output Handling",
        "icon": "⚠️",
        "description": "Validate harmful outputs and RAG-based injection vulnerabilities",
        "folders": ["harmful_outputs", "rag"],
    },
    {
        "id": "LLM07",
        "name": "System Prompt Leakage",
        "icon": "📝",
        "description": "Attempt to extract hidden system prompts and instructions",
        "folders": ["prompts"],
    },
    {
        "id": "LLM09",
        "name": "Misinformation",
        "icon": "🎭",
        "description": "Test for generation of false, misleading, or hallucinated content",
        "folders": ["misinformation"],
    },
    {
        "id": "LLM10",
        "name": "Unbounded Consumption",
        "icon": "⚡",
        "description": "Find rate limits and test for denial-of-service vulnerabilities",
        "folders": [],
    },
]

TESTS_BY_ID = {test["id"]: test for test in OWASP_TESTS}

app = Flask(__name__)


def _safe_path_from_base(user_path: str) -> Path:
    candidate = (BASE_DIR / user_path).resolve()
    if not str(candidate).startswith(str(BASE_DIR.resolve())):
        raise ValueError("Invalid file path")
    return candidate


def _list_csv_files(test_id: str) -> list[str]:
    test = TESTS_BY_ID[test_id]
    files: list[str] = []
    for folder in test["folders"]:
        folder_path = BASE_DIR / folder
        if folder_path.exists():
            for csv_file in sorted(folder_path.glob("*.csv")):
                files.append(str(csv_file.relative_to(BASE_DIR)))
    return files


def _parse_prompt_results(output_file: Path) -> dict:
    total = 0
    successful = 0
    injection_success = 0

    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    total = len(rows)
    for row in rows:
        response = row.get("response", "")
        if not response.startswith("ERROR:"):
            successful += 1
        if row.get("phrase_check") == "SUCCESS":
            injection_success += 1

    return {
        "totalRequests": total,
        "successful": successful,
        "failed": total - successful,
        "injectionSuccess": injection_success,
    }


def _parse_judged_results(output_file: Path) -> dict:
    total = 0
    successful = 0
    injection_success = 0
    possible = 0
    judge_errors = 0

    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    total = len(rows)
    for row in rows:
        response = row.get("response", "")
        if not response.startswith("ERROR:"):
            successful += 1

        label = (row.get("injection_label") or "").strip().upper()
        if label == "SUCCESS":
            injection_success += 1
        elif label == "POSSIBLE":
            possible += 1
        elif label == "ERROR":
            judge_errors += 1

    return {
        "totalRequests": total,
        "successful": successful,
        "failed": total - successful,
        "injectionSuccess": injection_success,
        "possibleInjection": possible,
        "judgeErrors": judge_errors,
    }


def _has_judgment_columns(output_file: Path) -> bool:
    with output_file.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
    required = {"injection_label", "injection_confidence", "injection_reasons"}
    return required.issubset(set(fieldnames))


def _parse_rate_limit_output(stdout: str) -> dict:
    def pick_int(pattern: str, default: int = 0) -> int:
        match = re.search(pattern, stdout)
        return int(match.group(1)) if match else default

    total = pick_int(r"Total requests sent:\s+(\d+)")
    successful = pick_int(r"Successful responses:\s+(\d+)")
    failed = total - successful
    return {
        "totalRequests": total,
        "successful": successful,
        "failed": max(failed, 0),
        "injectionSuccess": 0,
    }


def _logs_from_output(stdout: str, stderr: str) -> list[dict]:
    logs: list[dict] = []
    now = datetime.now().strftime("%H:%M:%S")
    for line in stdout.splitlines()[-20:]:
        if line.strip():
            logs.append({"timestamp": now, "message": line.strip(), "type": "info"})
    for line in stderr.splitlines()[-10:]:
        if line.strip():
            logs.append({"timestamp": now, "message": line.strip(), "type": "error"})
    return logs


@app.get("/")
def index():
    return send_from_directory(str(BASE_DIR / "html"), "llm_safety_dashboard.html")


@app.get("/api/tests")
def get_tests():
    return jsonify({"tests": OWASP_TESTS, "defaultUrl": DEFAULT_URL})


@app.get("/api/files")
def get_files():
    test_id = request.args.get("control", "").strip()
    if test_id not in TESTS_BY_ID:
        return jsonify({"error": "Invalid control id"}), 400
    return jsonify({"files": _list_csv_files(test_id)})


@app.post("/api/run")
def run_test():
    payload = request.get_json(silent=True) or {}
    test_id = str(payload.get("testId", "")).strip()
    target_url = str(payload.get("url", DEFAULT_URL)).strip() or DEFAULT_URL
    rate = str(payload.get("rate", "30")).strip() or "30"
    repeat = str(payload.get("repeat", "1")).strip() or "1"
    num_requests = str(payload.get("numRequests", "50")).strip() or "50"
    csv_file = str(payload.get("csvFile", "")).strip()

    if test_id not in TESTS_BY_ID:
        return jsonify({"error": "Unknown test type"}), 400

    try:
        if test_id == "LLM10":
            cmd = [
                sys.executable,
                str(SCRIPTS_DIR / "Rate-limit.py"),
                num_requests,
                rate,
                "-u",
                target_url,
            ]
            completed = subprocess.run(
                cmd,
                cwd=BASE_DIR,
                capture_output=True,
                text=True,
                timeout=1800,
            )
            stats = _parse_rate_limit_output(completed.stdout)
            logs = _logs_from_output(completed.stdout, completed.stderr)
            status = "success" if completed.returncode == 0 else "error"
            return jsonify(
                {
                    "status": status,
                    **stats,
                    "logs": logs,
                    "outputFile": None,
                }
            )

        if not csv_file:
            return jsonify({"error": "Please select a CSV test file"}), 400

        csv_path = _safe_path_from_base(csv_file)
        if not csv_path.exists() or csv_path.suffix.lower() != ".csv":
            return jsonify({"error": "Invalid CSV file"}), 400

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_name = f"results_{test_id}_{csv_path.stem}_{timestamp}.csv"
        output_file = BASE_DIR / output_name

        cmd = [
            sys.executable,
            str(SCRIPTS_DIR / "prompt_tester.py"),
            rate,
            str(csv_path),
            "-u",
            target_url,
            "-o",
            str(output_file),
            "-r",
            repeat,
        ]

        completed = subprocess.run(
            cmd,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=1800,
        )

        if not output_file.exists():
            logs = _logs_from_output(completed.stdout, completed.stderr)
            return (
                jsonify(
                    {
                        "status": "error",
                        "error": "Test run did not produce a results file",
                        "totalRequests": 0,
                        "successful": 0,
                        "failed": 0,
                        "injectionSuccess": 0,
                        "logs": logs,
                        "outputFile": None,
                    }
                ),
                500,
            )

        logs = _logs_from_output(completed.stdout, completed.stderr)
        logs.append(
            {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "message": f"Results saved to {output_name}",
                "type": "success",
            }
        )

        # Auto-run injection judge after results are written.
        judge_cmd = [
            sys.executable,
            str(SCRIPTS_DIR / "injection_judge.py"),
            str(output_file),
            "-u",
            DEFAULT_JUDGE_URL,
            "-m",
            DEFAULT_JUDGE_MODEL,
        ]
        judge_completed = subprocess.run(
            judge_cmd,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        logs.extend(_logs_from_output(judge_completed.stdout, judge_completed.stderr))
        judged_file_ready = _has_judgment_columns(output_file)
        if judge_completed.returncode == 0 and judged_file_ready:
            logs.append(
                {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "message": "Injection judge completed and final CSV was updated.",
                    "type": "success",
                }
            )
        else:
            logs.append(
                {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "message": "Injection judge did not produce judged columns. Returning pre-judged metrics.",
                    "type": "error",
                }
            )

        stats = _parse_judged_results(output_file) if judged_file_ready else _parse_prompt_results(output_file)
        judge_totally_failed = (
            judged_file_ready
            and stats.get("totalRequests", 0) > 0
            and stats.get("judgeErrors", 0) == stats.get("totalRequests", 0)
        )
        if judge_totally_failed:
            logs.append(
                {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "message": "Judge could not score any row. Check OPENAI_API_KEY and judge URL/model settings.",
                    "type": "error",
                }
            )
        status = "success" if completed.returncode == 0 and judged_file_ready and not judge_totally_failed else "error"
        return jsonify(
            {
                "status": status,
                **stats,
                "logs": logs,
                "outputFile": output_name,
            }
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Test timed out"}), 504
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # broad catch to keep UI responsive
        return jsonify({"error": f"Unexpected server error: {exc}"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
