#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from eval_enriched_dataset import build_solc_args_and_remaps, run_one, ROOT, SOLC_DEFAULT


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate prevalence-oriented ERC-4337 dataset")
    parser.add_argument("--dataset-dir", required=True)
    parser.add_argument("--python-bin", default=str(ROOT / ".venv" / "bin" / "python"))
    parser.add_argument("--solc", default=SOLC_DEFAULT)
    args = parser.parse_args()

    ds = Path(args.dataset_dir)
    manifest = json.loads((ds / "manifest.json").read_text(encoding="utf-8"))
    contracts = manifest["contracts"]
    src_root = Path(manifest["source_root"])

    results_dir = ds / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    details = []
    rc = Counter()
    ok = fail = with_find = total_findings = 0
    for c in contracts:
        src = Path(c["file"])
        out = results_dir / (src.name + "." + str(abs(hash(str(src)))) + ".json")
        solc_args, remaps = build_solc_args_and_remaps(src, src_root)
        rec = run_one(args.python_bin, args.solc, src, out, solc_args, remaps)
        rec["repo"] = c.get("repo", "")
        rec["relative_path"] = c.get("relative_path", "")
        rec["selection_reason"] = c.get("reason", "")
        details.append(rec)
        if rec["exit_code"] == 0:
            ok += 1
        else:
            fail += 1
        if rec["total_findings"] > 0:
            with_find += 1
        total_findings += rec["total_findings"]
        for k, v in rec["summary"].items():
            rc[k] += int(v)

    summary = {
        "dataset": manifest["dataset_name"],
        "contracts_total": len(contracts),
        "contracts_ok": ok,
        "contracts_failed": fail,
        "contracts_with_findings": with_find,
        "total_findings": total_findings,
        "findings_by_rule": dict(rc),
        "prevalence": {
            "among_all_selected": with_find / len(contracts) if contracts else 0.0,
            "among_analyzable": with_find / ok if ok else 0.0,
        },
    }
    (results_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (results_dir / "details.json").write_text(json.dumps(details, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
