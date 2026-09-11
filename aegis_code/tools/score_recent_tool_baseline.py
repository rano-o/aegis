#!/usr/bin/env python3

import argparse
import json
from pathlib import Path


def load_json(path):
    with open(path) as f:
        return json.load(f)


def metric_div(num, den):
    return 0.0 if den == 0 else num / den


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-json", required=True)
    parser.add_argument("--eval-input-json", required=True)
    parser.add_argument("--decontaminated-json", required=True)
    parser.add_argument("--tool-name", required=True)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()

    raw = load_json(args.raw_json)
    eval_input = load_json(args.eval_input_json)
    decont = load_json(args.decontaminated_json)

    gt = eval_input["gt_vuln_by_file"]
    excluded = set(decont["excluded_files"])
    included_files = [f for f in eval_input["files"] if f not in excluded]

    tp = fp = tn = fn = 0
    missing = []
    timeouts = 0
    parse_failures = 0
    flagged_files = 0

    for file_path in included_files:
        row = raw.get(file_path)
        if row is None:
            missing.append(file_path)
            pred = False
        else:
            pred = bool(row.get("flagged", False))
            if row.get("timeout"):
                timeouts += 1
            if row.get("parse_ok") is False:
                parse_failures += 1
            if pred:
                flagged_files += 1
        truth = bool(gt[file_path])
        if pred and truth:
            tp += 1
        elif pred and not truth:
            fp += 1
        elif (not pred) and truth:
            fn += 1
        else:
            tn += 1

    precision = metric_div(tp, tp + fp)
    recall = metric_div(tp, tp + fn)
    f1 = metric_div(2 * precision * recall, precision + recall)

    out = {
        "tool": args.tool_name,
        "scope": "decontaminated",
        "included_files": len(included_files),
        "excluded_files": len(excluded),
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "flagged_files": flagged_files,
        "timeouts": timeouts,
        "parse_failures": parse_failures,
        "missing_raw_rows": len(missing),
        "missing_raw_examples": missing[:10],
    }

    out_path = Path(args.output_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
