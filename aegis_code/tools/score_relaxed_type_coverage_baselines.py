#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


RULES = ["VU001", "VU002", "VU003", "VU004", "VU005", "VU007"]

COVERAGE_KEYWORDS = {
    "VU001": [
        "signature",
        "signer",
        "ecdsa",
        "recover",
        "auth",
        "authentication",
        "authorization",
        "access control",
        "verify",
        "verification",
    ],
    "VU002": ["nonce", "replay", "anti-replay", "freshness", "sequence"],
    "VU003": [
        "return 0",
        "returns 0",
        "return success",
        "returns success",
        "constant success",
        "always true",
        "always valid",
        "sigvalidationfailed",
    ],
    "VU004": [
        "userophash",
        "hash",
        "message hash",
        "digest",
        "domain",
        "keccak",
        "typed data",
        "recompute",
    ],
    "VU005": [
        "nonce update",
        "increment nonce",
        "consume nonce",
        "replay",
        "state update",
    ],
    "VU007": [
        "entrypoint",
        "msg.sender",
        "caller",
        "onlyentrypoint",
        "fromentrypoint",
        "requirefromentrypoint",
        "access control",
        "unauthorized caller",
    ],
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


def normalized_text(*parts: str) -> str:
    return " ".join(p for p in parts if p).lower()


def matches_rule_coverage(text: str, rule: str) -> bool:
    keywords = COVERAGE_KEYWORDS[rule]
    return any(k in text for k in keywords)


def semgrep_alerts(
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
        text = normalized_text(
            rec.get("check_id", ""), rec.get("extra", {}).get("message", "")
        )
        by_file.setdefault(file_path, []).append(text)
    return by_file


def solhint_alerts(
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
            text = normalized_text(rec.get("ruleId", ""), rec.get("message", ""))
            by_file.setdefault(file_path, []).append(text)
    return by_file


def tameshi_alerts(
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
            in_span = False
            for loc in locations:
                line = loc.get("line")
                if isinstance(line, int) and span[0] <= line <= span[1]:
                    in_span = True
                    break
            if not in_span:
                continue
            text = normalized_text(
                rec.get("scanner_id", ""),
                rec.get("finding_type", ""),
                rec.get("title", ""),
                rec.get("description", ""),
            )
            by_file.setdefault(file_path, []).append(text)
    return by_file


def detailed_tool_alerts(
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
            text = normalized_text(rec.get("rule_id", ""), rec.get("message", ""))
            by_file.setdefault(file_path, []).append(text)
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
        alerts_by_file = semgrep_alerts(raw_path, spans)
    elif args.tool == "solhint":
        alerts_by_file = solhint_alerts(raw_path, spans)
    elif args.tool == "tameshi":
        alerts_by_file = tameshi_alerts(raw_path, spans)
    else:
        alerts_by_file = detailed_tool_alerts(raw_path, spans)

    per_rule_counts = {rule: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for rule in RULES}
    covered_examples = []
    for row in gold_rows:
        file_path = row["file"]
        alert_texts = alerts_by_file.get(file_path, [])
        for rule in RULES:
            gt = bool(row["gt_rules"][rule])
            pred = any(matches_rule_coverage(text, rule) for text in alert_texts)
            if pred and gt:
                per_rule_counts[rule]["tp"] += 1
                if len(covered_examples) < 20:
                    covered_examples.append(
                        {
                            "file": file_path,
                            "rule": rule,
                            "rationale": row.get("rationale", ""),
                            "alerts": alert_texts[:3],
                        }
                    )
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
        "granularity": "relaxed-function-type-coverage",
        "matching_policy": "alert line must fall inside validateUserOp and alert text may use broader vulnerability-family wording that covers the target VU type",
        "rules": rules_out,
        "micro": metric_entry(**micro),
        "covered_example_count": len(covered_examples),
        "covered_examples": covered_examples,
        "scored_files": len(gold_rows),
    }

    out_path = Path(args.output_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
