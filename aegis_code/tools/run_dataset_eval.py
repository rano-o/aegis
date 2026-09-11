#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANALYZER = ROOT / "src" / "aa4337_analyzer.py"
DATASET_DIR = ROOT / "datasets" / "real_small"
MANIFEST = DATASET_DIR / "manifest.json"
RESULTS_DIR = DATASET_DIR / "results"


def run_one(sol_file: Path, source_root: Path, solc: str, python_bin: str) -> dict:
    out_file = RESULTS_DIR / (sol_file.as_posix().replace("/", "__") + ".json")
    cmd = [
        python_bin,
        str(ANALYZER),
        str(source_root / sol_file),
        "--solc",
        solc,
        "--solc-remaps",
        "@openzeppelin/=datasets/real_small/vendor/@openzeppelin/,@uniswap/v3-periphery/contracts/=datasets/real_small/vendor/@uniswap/v3-periphery/,@uniswap/v3-core/contracts/=datasets/real_small/vendor/@uniswap/v3-core/",
        "--solc-args",
        "--base-path /Users/chenting/aa-sentry --include-path /Users/chenting/aa-sentry/datasets/real_small/vendor --include-path /Users/chenting/aa-sentry/datasets/real_small/sources/account-abstraction",
        "--json-out",
        str(out_file),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    record = {
        "contract": str(sol_file),
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "result_file": str(out_file),
    }
    if out_file.exists():
        payload = json.loads(out_file.read_text(encoding="utf-8"))
        record["total_findings"] = payload.get("total_findings", 0)
        record["summary"] = payload.get("summary", {})
    else:
        record["total_findings"] = 0
        record["summary"] = {}
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description="Run phase-1 analyzer on real_small dataset")
    parser.add_argument("--solc", required=True, help="solc binary path")
    parser.add_argument("--python-bin", default=str(ROOT / ".venv" / "bin" / "python"), help="python executable")
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    source_root = Path(manifest["source_local_path"])
    contracts = [Path(p) for p in manifest["contracts"]]

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    results = [run_one(c, source_root, args.solc, args.python_bin) for c in contracts]

    ok = [r for r in results if r["exit_code"] == 0]
    failed = [r for r in results if r["exit_code"] != 0]

    rule_counter: Counter[str] = Counter()
    total_findings = 0
    contracts_with_findings = 0
    for r in ok:
        total_findings += r.get("total_findings", 0)
        if r.get("total_findings", 0) > 0:
            contracts_with_findings += 1
        for k, v in r.get("summary", {}).items():
            rule_counter[k] += int(v)

    summary = {
        "dataset": manifest["dataset_name"],
        "contracts_total": len(contracts),
        "contracts_ok": len(ok),
        "contracts_failed": len(failed),
        "contracts_with_findings": contracts_with_findings,
        "total_findings": total_findings,
        "findings_by_rule": dict(rule_counter),
        "failed_contracts": [{"contract": f["contract"], "exit_code": f["exit_code"]} for f in failed],
    }

    summary_path = RESULTS_DIR / "summary.json"
    details_path = RESULTS_DIR / "details.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    details_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print(f"summary: {summary_path}")
    print(f"details: {details_path}")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
