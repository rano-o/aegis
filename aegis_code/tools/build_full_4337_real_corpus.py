#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_ROOT = ROOT / "datasets" / "aa4337_large_prod" / "sources"
DEFAULT_DISCOVERY = ROOT / "datasets" / "aa4337_large_prod" / "discovery" / "discovered_repos.json"
DEFAULT_OUT_DIR = ROOT / "datasets" / "aa4337_full_real"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_json(path: Path, fallback):
    if not path.exists():
        return fallback
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback


def build(source_root: Path, discovery_file: Path, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    results_dir = out_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    discovery = _load_json(discovery_file, {"repos": [], "queries": [], "org_seeds": []})
    repos_from_discovery = discovery.get("repos", [])
    by_repo_name = {
        r.get("nameWithOwner", "").split("/")[-1]: r
        for r in repos_from_discovery
        if isinstance(r, dict)
    }

    repo_dirs = sorted([p for p in source_root.iterdir() if p.is_dir()])
    contracts = []
    exact_hash_seen: dict[str, str] = {}
    duplicate_exact = 0
    repo_contract_counts = Counter()

    for repo_dir in repo_dirs:
        repo = repo_dir.name
        for sol in repo_dir.rglob("*.sol"):
            if not sol.is_file():
                continue
            try:
                raw = sol.read_bytes()
            except Exception:
                continue
            h = _sha256_bytes(raw)
            rel = sol.relative_to(source_root)
            rec = {
                "file": str(sol),
                "relative_path": str(rel),
                "repo": repo,
                "sha256": h,
                "source": by_repo_name.get(repo, {}),
            }
            if h in exact_hash_seen:
                duplicate_exact += 1
                rec["duplicate_of"] = exact_hash_seen[h]
            else:
                exact_hash_seen[h] = str(rel)
            contracts.append(rec)
            repo_contract_counts[repo] += 1

    manifest = {
        "dataset_name": "aa4337_full_real",
        "description": "Full-scale real ERC-4337-related Solidity corpus from collected open-source repositories",
        "source_root": str(source_root),
        "discovery_file": str(discovery_file),
        "queries": discovery.get("queries", []),
        "org_seeds": discovery.get("org_seeds", []),
        "repos_total": len(repo_dirs),
        "contracts_total": len(contracts),
        "contracts": contracts,
        "stats": {
            "repos_total": len(repo_dirs),
            "contracts_total": len(contracts),
            "exact_unique_hashes": len(exact_hash_seen),
            "exact_duplicate_files": duplicate_exact,
            "by_repo_contract_count": dict(repo_contract_counts),
        },
    }

    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (results_dir / "repo_list.json").write_text(
        json.dumps([str(p.relative_to(source_root)) for p in repo_dirs], indent=2),
        encoding="utf-8",
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build full real ERC-4337 Solidity corpus manifest")
    parser.add_argument("--source-root", default=str(DEFAULT_SOURCE_ROOT))
    parser.add_argument("--discovery-file", default=str(DEFAULT_DISCOVERY))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    args = parser.parse_args()

    manifest = build(Path(args.source_root), Path(args.discovery_file), Path(args.out_dir))
    print(json.dumps({
        "dataset": manifest["dataset_name"],
        "repos_total": manifest["repos_total"],
        "contracts_total": manifest["contracts_total"],
        "manifest": str(Path(args.out_dir) / "manifest.json"),
        "stats": manifest["stats"],
    }, indent=2))


if __name__ == "__main__":
    main()
