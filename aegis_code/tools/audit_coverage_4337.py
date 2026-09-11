#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


ALIAS_MAP = {
    "base-paymaster": "base/paymaster",
    "verifying-paymaster": "coinbase/verifying-paymaster",
    "ithaca-account": "ithacaxyz/account",
    "passkeys-smart-wallet": "passkeys-4337/smart-wallet",
    "erc4337-contracts-v07": "gelatodigital/erc4337-contracts-v07",
    "artela-account-abstraction": "artela-network/account-abstraction",
    "stackup-contracts": "stackup-wallet/contracts",
}


ROOT = Path(__file__).resolve().parents[1]


def _normalize_repo_name(name: str) -> str:
    return name.strip().lower()


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit coverage of built ERC-4337 dataset against discovered repositories")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--discovery", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    discovery = json.loads(Path(args.discovery).read_text(encoding="utf-8"))

    cloned_ok = {
        _normalize_repo_name(x["name"]): x
        for x in manifest.get("clone_logs", [])
        if x.get("ok")
    }
    cloned_fail = {
        _normalize_repo_name(x["name"]): x
        for x in manifest.get("clone_logs", [])
        if not x.get("ok")
    }

    discovered = discovery.get("repos", [])
    discovered_full = [r.get("nameWithOwner", "") for r in discovered if r.get("nameWithOwner")]
    discovered_short = {_normalize_repo_name(x.split("/")[-1]): x for x in discovered_full}

    for alias, full in ALIAS_MAP.items():
        if alias in cloned_ok:
            discovered_short[_normalize_repo_name(alias)] = full

    covered = []
    failed = []
    missing = []
    cloned_full = {
        _normalize_repo_name(ALIAS_MAP.get(name, name)): name
        for name in list(cloned_ok.keys()) + list(cloned_fail.keys())
    }

    for short, full in discovered_short.items():
        full_norm = _normalize_repo_name(full)
        short_norm = _normalize_repo_name(short)
        if short_norm in cloned_ok or full_norm in cloned_full:
            covered.append(full)
        elif short_norm in cloned_fail:
            failed.append(full)
        else:
            missing.append(full)

    by_repo = Counter(c["repo"] for c in manifest.get("contracts", []))

    out = {
        "manifest": args.manifest,
        "discovery": args.discovery,
        "discovered_total": len(discovered_short),
        "covered_count": len(covered),
        "failed_count": len(failed),
        "missing_count": len(missing),
        "covered_repos": sorted(covered),
        "failed_repos": sorted(failed),
        "missing_repos": sorted(missing),
        "dataset_contracts_total": manifest.get("total_contracts", 0),
        "contracts_per_repo": dict(by_repo),
        "coverage_ratio_discovered": (len(covered) / len(discovered_short)) if discovered_short else 0.0,
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps({
        "out": str(out_path),
        "discovered_total": out["discovered_total"],
        "covered": out["covered_count"],
        "failed": out["failed_count"],
        "missing": out["missing_count"],
        "coverage_ratio_discovered": out["coverage_ratio_discovered"],
    }, indent=2))


if __name__ == "__main__":
    main()
