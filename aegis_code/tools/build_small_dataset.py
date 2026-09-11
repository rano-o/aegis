#!/usr/bin/env python3
from __future__ import annotations

import json
import random
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "datasets" / "real_small"
SOURCE_CONTRACTS = DATASET_DIR / "sources" / "account-abstraction" / "contracts"
MANIFEST_PATH = DATASET_DIR / "manifest.json"


def _all_sol_files() -> list[Path]:
    return sorted(SOURCE_CONTRACTS.rglob("*.sol"))


def build_manifest(target_count: int = 80, seed: int = 4337) -> dict:
    files = _all_sol_files()
    if not files:
        raise RuntimeError(f"No solidity files found under: {SOURCE_CONTRACTS}")

    random.seed(seed)

    priority = [
        p
        for p in files
        if any(part in str(p).lower() for part in ["/core/", "/accounts/", "/interfaces/", "entrypoint", "paymaster", "useroperation"])
    ]

    selected: list[Path] = []
    seen = set()
    for p in priority:
        rp = p.relative_to(SOURCE_CONTRACTS)
        if rp not in seen:
            selected.append(p)
            seen.add(rp)

    remaining = [p for p in files if p.relative_to(SOURCE_CONTRACTS) not in seen]
    random.shuffle(remaining)

    for p in remaining:
        if len(selected) >= target_count:
            break
        selected.append(p)

    selected = selected[:target_count]

    manifest = {
        "dataset_name": "aa_phase1_real_small",
        "description": "Real Solidity contracts sampled for Phase-1 validation (<=100 files)",
        "source_repo": "https://github.com/eth-infinitism/account-abstraction",
        "source_local_path": str(SOURCE_CONTRACTS),
        "sample_seed": seed,
        "target_count": target_count,
        "actual_count": len(selected),
        "contracts": [str(p.relative_to(SOURCE_CONTRACTS)) for p in selected],
    }
    return manifest


def main() -> None:
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    manifest = build_manifest()
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"wrote manifest: {MANIFEST_PATH}")
    print(f"contracts: {manifest['actual_count']}")


if __name__ == "__main__":
    main()
