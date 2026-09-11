#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


RULES = ["VU001", "VU002", "VU003", "VU004", "VU005", "VU007"]

TYPE_ID_KEYWORDS = {
    "VU001": ["vu001", "erc4337-vu001", "aa-vu001"],
    "VU002": ["vu002", "erc4337-vu002", "aa-vu002"],
    "VU003": ["vu003", "erc4337-vu003", "aa-vu003"],
    "VU004": ["vu004", "erc4337-vu004", "aa-vu004"],
    "VU005": ["vu005", "erc4337-vu005", "aa-vu005"],
    "VU007": ["vu007", "erc4337-vu007", "aa-vu007"],
}


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


def norm(s: str) -> str:
    return (s or "").lower()


def id_matches_rule(detector_id: str, rule: str) -> bool:
    d = norm(detector_id)
    return any(k in d for k in TYPE_ID_KEYWORDS[rule])


def semgrep_ids_by_file(
    raw_path: Path, spans: Dict[str, Tuple[int, int]]
) -> Dict[str, List[str]]:
    payload = load_json(raw_path)
    by_file: Dict[str, List[str]] = {}
    for rec in payload.get("results", []):
        file_path = rec.get("path")
        span = spans.get(file_path)
        if not span:
            continue
        line = rec.get("start", {}).get("line")
        if not isinstance(line, int) or not (span[0] <= line <= span[1]):
            continue
        by_file.setdefault(file_path, []).append(norm(rec.get("check_id", "")))
    return by_file


def solhint_ids_by_file(
    raw_path: Path, spans: Dict[str, Tuple[int, int]]
) -> Dict[str, List[str]]:
    payload = load_json(raw_path)
    by_file: Dict[str, List[str]] = {}
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
            if not isinstance(line, int) or not (span[0] <= line <= span[1]):
                continue
            by_file.setdefault(file_path, []).append(norm(rec.get("ruleId", "")))
    return by_file


def tameshi_ids_by_file(
    raw_path: Path, spans: Dict[str, Tuple[int, int]]
) -> Dict[str, List[str]]:
    payload = load_json(raw_path)
    by_file: Dict[str, List[str]] = {}
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
            if not any(
                isinstance(loc.get("line"), int)
                and span[0] <= loc.get("line") <= span[1]
                for loc in locations
            ):
                continue
            det = (
                norm(rec.get("scanner_id", ""))
                + " "
                + norm(rec.get("finding_type", ""))
            )
            by_file.setdefault(file_path, []).append(det.strip())
    return by_file


def detailed_ids_by_file(
    raw_path: Path, spans: Dict[str, Tuple[int, int]]
) -> Dict[str, List[str]]:
    payload = load_json(raw_path)
    by_file: Dict[str, List[str]] = {}
    for file_path, row in payload.items():
        span = spans.get(file_path)
        if not span:
            continue
        findings = row.get("findings", []) if isinstance(row, dict) else []
        for rec in findings:
            line = rec.get("line")
            if not isinstance(line, int) or not (span[0] <= line <= span[1]):
                continue
            by_file.setdefault(file_path, []).append(norm(rec.get("rule_id", "")))
    return by_file


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
        ids_by_file = semgrep_ids_by_file(raw_path, spans)
    elif args.tool == "solhint":
        ids_by_file = solhint_ids_by_file(raw_path, spans)
    elif args.tool == "tameshi":
        ids_by_file = tameshi_ids_by_file(raw_path, spans)
    else:
        ids_by_file = detailed_ids_by_file(raw_path, spans)

    per_rule_counts = {rule: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for rule in RULES}
    for row in gold_rows:
        file_path = row["file"]
        det_ids = ids_by_file.get(file_path, [])
        for rule in RULES:
            gt = bool(row["gt_rules"][rule])
            pred = any(id_matches_rule(det_id, rule) for det_id in det_ids)
            if pred and gt:
                per_rule_counts[rule]["tp"] += 1
            elif pred and not gt:
                per_rule_counts[rule]["fp"] += 1
            elif (not pred) and gt:
                per_rule_counts[rule]["fn"] += 1
            else:
                per_rule_counts[rule]["tn"] += 1

    micro = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    rules_out = {}
    for rule, counts in per_rule_counts.items():
        rules_out[rule] = metric_entry(**counts)
        for k in micro:
            micro[k] += counts[k]

    out = {
        "tool": args.tool,
        "granularity": "typed-p-first-function-level",
        "matching_policy": "a positive prediction exists only if the tool detector identifier explicitly indicates the target vulnerability family; then TP/FP decided against gold at function scope",
        "rules": rules_out,
        "micro": metric_entry(**micro),
        "scored_files": len(gold_rows),
    }

    out_path = Path(args.output_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
