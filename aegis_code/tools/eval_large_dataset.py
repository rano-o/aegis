#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANALYZER = ROOT / "src" / "aa4337_analyzer.py"


def run_one(
    analyzer: Path,
    python_bin: str,
    sol_file: Path,
    repo_root: Path,
    solc: str,
    result_file: Path,
    solc_args: str,
    solc_remaps: str,
) -> dict:
    cmd = [
        python_bin,
        str(analyzer),
        str(sol_file),
        "--solc",
        solc,
        "--solc-args",
        solc_args,
        "--solc-remaps",
        solc_remaps,
        "--json-out",
        str(result_file),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(repo_root))
    rec = {
        "file": str(sol_file),
        "exit_code": proc.returncode,
        "stdout": proc.stdout[-1000:],
        "stderr": proc.stderr[-1000:],
        "result_file": str(result_file),
        "total_findings": 0,
        "summary": {},
        "strategy": "repo_compile",
    }
    if result_file.exists():
        payload = json.loads(result_file.read_text(encoding="utf-8"))
        rec["total_findings"] = payload.get("total_findings", 0)
        rec["summary"] = payload.get("summary", {})
    if rec["exit_code"] == 0:
        return rec

    with tempfile.TemporaryDirectory(prefix="aa4337_eval_") as td:
        fallback_out = Path(td) / "fallback.json"
        fallback_cmd = [
            python_bin,
            str(analyzer),
            str(sol_file),
            "--solc",
            solc,
            "--solc-args",
            solc_args,
            "--solc-remaps",
            solc_remaps,
            "--json-out",
            str(fallback_out),
        ]
        fallback_proc = subprocess.run(fallback_cmd, capture_output=True, text=True, cwd=str(ROOT))
        if fallback_proc.returncode == 0 and fallback_out.exists():
            payload = json.loads(fallback_out.read_text(encoding="utf-8"))
            result_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            rec = {
                "file": str(sol_file),
                "exit_code": 0,
                "stdout": fallback_proc.stdout[-1000:],
                "stderr": fallback_proc.stderr[-1000:],
                "result_file": str(result_file),
                "total_findings": payload.get("total_findings", 0),
                "summary": payload.get("summary", {}),
                "strategy": "fallback_remap",
            }
    return rec


def main() -> None:
    parser = argparse.ArgumentParser(description="Run phase-1 analyzer on large ERC-4337 dataset")
    parser.add_argument("--dataset-dir", required=True)
    parser.add_argument("--solc", required=True)
    parser.add_argument("--python-bin", default=str(ROOT / ".venv" / "bin" / "python"))
    parser.add_argument("--limit", type=int, default=0, help="Optional limit for quick runs")
    args = parser.parse_args()

    ds = Path(args.dataset_dir)
    manifest = json.loads((ds / "manifest.json").read_text(encoding="utf-8"))
    contracts = manifest.get("contracts", [])
    if args.limit > 0:
        contracts = contracts[: args.limit]

    results_dir = ds / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    details = []
    rule_counter: Counter[str] = Counter()
    total_findings = 0
    ok = 0
    fail = 0
    with_findings = 0

    global_include = (
        f"--base-path {ROOT} "
        f"--include-path {ds / 'sources'} "
        f"--include-path {ds / 'contracts'}"
    )
    remaps = ",".join(
        [
            f"@openzeppelin/={ds / 'sources' / 'openzeppelin-contracts' / 'contracts'}/",
            f"@openzeppelin/contracts/={ds / 'sources' / 'openzeppelin-contracts' / 'contracts'}/",
            f"@uniswap/v3-core/contracts/={ds / 'sources' / 'uniswap-v3-core' / 'contracts'}/",
            f"@uniswap/v3-periphery/contracts/={ds / 'sources' / 'uniswap-v3-periphery' / 'contracts'}/",
            f"@account-abstraction/contracts/={ds / 'sources' / 'account-abstraction' / 'contracts'}/",
        ]
    )

    for c in contracts:
        repo_root = ds / "sources" / c["repo"]
        sol_file = repo_root / c["source_path"]
        out = results_dir / (c["dataset_path"].replace("/", "__") + ".json")
        rec = run_one(ANALYZER, args.python_bin, sol_file, repo_root, args.solc, out, global_include, remaps)
        details.append(rec)
        if rec["exit_code"] == 0:
            ok += 1
        else:
            fail += 1
        if rec["total_findings"] > 0:
            with_findings += 1
        total_findings += rec["total_findings"]
        for k, v in rec["summary"].items():
            rule_counter[k] += int(v)

    summary = {
        "dataset": manifest.get("dataset_name", "aa4337_large"),
        "contracts_total": len(contracts),
        "contracts_ok": ok,
        "contracts_failed": fail,
        "contracts_with_findings": with_findings,
        "total_findings": total_findings,
        "findings_by_rule": dict(rule_counter),
    }
    (results_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (results_dir / "details.json").write_text(json.dumps(details, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
