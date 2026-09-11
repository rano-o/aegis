#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


RULES = ["VU001", "VU002", "VU003", "VU004", "VU005", "VU007"]
def _safe_ratio(num: int, den: int) -> float:
    return num / den if den else 0.0


def _f1(precision: float, recall: float) -> float:
    return 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _metric_entry(tp: int, fp: int, tn: int, fn: int) -> dict[str, float | int]:
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": _f1(precision, recall),
    }


def _collect_prediction_presence(details: list[dict]) -> tuple[dict[tuple[str, str, str], dict[str, bool]], dict[str, int]]:
    per_func: dict[tuple[str, str, str], dict[str, bool]] = {}
    rule_counts = {rule: 0 for rule in RULES}
    for rec in details:
        if int(rec.get("exit_code", 1)) != 0:
            continue
        result_file = rec.get("result_file", "")
        if not result_file:
            continue
        payload = _load_json(Path(result_file))
        seen_in_file: set[tuple[str, str, str, str]] = set()
        for finding in payload.get("findings", []):
            rule = finding.get("rule_id")
            if rule not in RULES:
                continue
            key = (
                finding.get("file", rec.get("file", "")),
                finding.get("contract", ""),
                finding.get("function", ""),
            )
            func_pred = per_func.setdefault(key, {r: False for r in RULES})
            func_pred[rule] = True
            unique_finding = (*key, rule)
            if unique_finding not in seen_in_file:
                seen_in_file.add(unique_finding)
                rule_counts[rule] += 1
    return per_func, rule_counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Recompute function-level VU001-VU007 metrics for enriched dataset")
    parser.add_argument("--dataset-dir", required=True)
    parser.add_argument("--gold-labels", default="")
    parser.add_argument("--labels-out", default="")
    parser.add_argument("--metrics-out", default="")
    args = parser.parse_args()

    dataset_dir = Path(args.dataset_dir)
    details = _load_json(dataset_dir / "results" / "details.json")
    summary = _load_json(dataset_dir / "results" / "summary.json")
    gold_path = Path(args.gold_labels) if args.gold_labels else dataset_dir / "results" / "manual_gold_labels_vu001_vu007.json"
    gold_labels = _load_json(gold_path)

    pred_by_func, predicted_counts = _collect_prediction_presence(details)
    summary_counts = {rule: int(summary.get("findings_by_rule", {}).get(rule, 0)) for rule in RULES}
    if summary_counts != predicted_counts:
        raise SystemExit(
            "Prediction count mismatch between finding JSONs and summary.json. "
            f"finding-derived={predicted_counts}, summary-derived={summary_counts}."
        )

    labels = []
    per_rule_counts = {rule: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for rule in RULES}

    for idx, gold in enumerate(gold_labels):
        source_file = gold["file"]
        function_name = gold.get("function", "validateUserOp")
        gold_contract = gold.get("contract", "")
        pred_rules = pred_by_func.get((source_file, gold_contract, function_name))
        if pred_rules is None:
            fallback = None
            for pred_key, pred in pred_by_func.items():
                pred_file, _pred_contract, pred_func = pred_key
                if pred_file == source_file and pred_func == function_name:
                    fallback = pred
                    gold_contract = pred_key[1]
                    break
            pred_rules = fallback or {rule: False for rule in RULES}

        gt_rules = gold["gt_rules"]
        labels.append(
            {
                "file": source_file,
                "function": function_name,
                "contract": gold_contract,
                "function_index": gold.get("function_index", idx),
                "pred_rules": pred_rules,
                "gt_rules": gt_rules,
                "rationale": gold.get("rationale", ""),
            }
        )

        for rule in RULES:
            pred = pred_rules[rule]
            gt = gt_rules[rule]
            if pred and gt:
                per_rule_counts[rule]["tp"] += 1
            elif pred and not gt:
                per_rule_counts[rule]["fp"] += 1
            elif (not pred) and gt:
                per_rule_counts[rule]["fn"] += 1
            else:
                per_rule_counts[rule]["tn"] += 1

    metrics = {"granularity": "function", "scope": "validateUserOp implementations only", "ground_truth": str(gold_path), "rules": {}, "micro": {}}
    micro = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for rule in RULES:
        counts = per_rule_counts[rule]
        metrics["rules"][rule] = _metric_entry(**counts)
        for key in micro:
            micro[key] += counts[key]
    metrics["micro"] = _metric_entry(**micro)

    labels_out = Path(args.labels_out) if args.labels_out else dataset_dir / "results" / "function_labels_vu001_vu007_manual.json"
    metrics_out = Path(args.metrics_out) if args.metrics_out else dataset_dir / "results" / "metrics_vu001_vu007_manual.json"
    labels_out.write_text(json.dumps(labels, indent=2), encoding="utf-8")
    metrics_out.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
