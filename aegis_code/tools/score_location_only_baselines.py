#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


RULES = ["VU001", "VU002", "VU003", "VU004", "VU005", "VU007"]


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def metric_div(num: float, den: float) -> float:
    return 0.0 if den == 0 else num / den


def f1(precision: float, recall: float) -> float:
    return metric_div(2 * precision * recall, precision + recall)


def extract_validate_userop_span(file_path: str) -> Optional[Tuple[int, int]]:
    text = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    m = re.search(
        r"function\s+validateUserOp\s*\((.*?)\)\s*([^{};]*?)\{",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if not m:
        return None
    brace = m.end() - 1
    depth = 0
    i = brace
    while i < len(text):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    start_line = text.count("\n", 0, m.start()) + 1
    end_line = text.count("\n", 0, i) + 1
    return start_line, end_line


def semgrep_flagged_files(
    raw_path: Path, spans: Dict[str, Tuple[int, int]]
) -> Dict[str, bool]:
    payload = load_json(raw_path)
    flagged: Dict[str, bool] = {}
    for rec in payload.get("results", []):
        file_path = rec.get("path")
        span = spans.get(file_path)
        if not span:
            continue
        line = rec.get("start", {}).get("line")
        if isinstance(line, int) and span[0] <= line <= span[1]:
            flagged[file_path] = True
    return flagged


def solhint_flagged_files(
    raw_path: Path, spans: Dict[str, Tuple[int, int]]
) -> Dict[str, bool]:
    payload = load_json(raw_path)
    flagged: Dict[str, bool] = {}
    for file_path, row in payload.items():
        span = spans.get(file_path)
        if not span:
            continue
        try:
            findings = json.loads((row.get("stdout") or "[]").strip() or "[]")
        except Exception:
            continue
        for rec in findings:
            line = rec.get("line")
            if isinstance(line, int) and span[0] <= line <= span[1]:
                flagged[file_path] = True
                break
    return flagged


def tameshi_flagged_files(
    raw_path: Path, spans: Dict[str, Tuple[int, int]]
) -> Dict[str, bool]:
    payload = load_json(raw_path)
    flagged: Dict[str, bool] = {}
    for file_path, row in payload.items():
        span = spans.get(file_path)
        if not span:
            continue
        try:
            findings = json.loads((row.get("stdout") or "[]").strip() or "[]")
        except Exception:
            continue
        for rec in findings:
            locations = rec.get("locations", [])
            if any(
                isinstance(loc.get("line"), int)
                and span[0] <= loc.get("line") <= span[1]
                for loc in locations
            ):
                flagged[file_path] = True
                break
    return flagged


def detailed_flagged_files(
    raw_path: Path, spans: Dict[str, Tuple[int, int]]
) -> Dict[str, bool]:
    payload = load_json(raw_path)
    flagged: Dict[str, bool] = {}
    for file_path, row in payload.items():
        span = spans.get(file_path)
        if not span:
            continue
        findings = row.get("findings", []) if isinstance(row, dict) else []
        for rec in findings:
            line = rec.get("line")
            if isinstance(line, int) and span[0] <= line <= span[1]:
                flagged[file_path] = True
                break
    return flagged


def metric_entry(tp: int, fp: int, tn: int, fn: int):
    precision = metric_div(tp, tp + fp)
    recall = metric_div(tp, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1(precision, recall),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--tool",
        required=True,
        choices=[
            "semgrep",
            "solhint",
            "tameshi",
            "slither",
            "aderyn",
            "mythril",
            "smartcheck",
            "soliditydefend",
        ],
    )
    parser.add_argument("--raw-json", required=True)
    parser.add_argument("--gold-json", required=True)
    parser.add_argument("--decontaminated-json", required=True)
    parser.add_argument("--eval-input-json", required=True)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()

    gold = load_json(Path(args.gold_json))
    decont = load_json(Path(args.decontaminated_json))
    eval_input = load_json(Path(args.eval_input_json))
    excluded = set(decont["excluded_files"])
    benchmark_files = set(eval_input["files"])

    gold_rows = [
        row
        for row in gold
        if row["file"] in benchmark_files and row["file"] not in excluded
    ]
    spans = {
        row["file"]: extract_validate_userop_span(row["file"]) for row in gold_rows
    }
    spans = {k: v for k, v in spans.items() if v is not None}

    raw_path = Path(args.raw_json)
    if args.tool == "semgrep":
        flagged = semgrep_flagged_files(raw_path, spans)
    elif args.tool == "solhint":
        flagged = solhint_flagged_files(raw_path, spans)
    elif args.tool == "tameshi":
        flagged = tameshi_flagged_files(raw_path, spans)
    else:
        flagged = detailed_flagged_files(raw_path, spans)

    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for row in gold_rows:
        file_path = row["file"]
        pred = bool(flagged.get(file_path, False))
        gt_any = any(bool(row["gt_rules"][r]) for r in RULES)
        if pred and gt_any:
            counts["tp"] += 1
        elif pred and not gt_any:
            counts["fp"] += 1
        elif (not pred) and gt_any:
            counts["fn"] += 1
        else:
            counts["tn"] += 1

    out = {
        "tool": args.tool,
        "granularity": "location-only-validateUserOp",
        "matching_policy": "any finding line inside validateUserOp counts as predicted-positive; ground truth positive if any target VU rule is true for that file",
        "file_level": metric_entry(**counts),
        "scored_files": len(gold_rows),
    }

    out_path = Path(args.output_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
