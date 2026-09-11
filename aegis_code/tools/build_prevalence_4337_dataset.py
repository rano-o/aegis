#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_ROOT = ROOT / "datasets" / "aa4337_large_prod" / "sources"
DEFAULT_DISCOVERY = ROOT / "datasets" / "aa4337_large_prod" / "discovery" / "discovered_repos.json"
DEFAULT_OUT = ROOT / "datasets" / "aa4337_prevalence_main"

FUNC_RE = re.compile(r"function\s+validateUserOp\s*\([^;{}]*\)\s*[^;{}]*\{", re.IGNORECASE | re.DOTALL)

EXCLUDE_PATH_PARTS = {
    "test", "tests", "script", "scripts", "mock", "mocks", "sample", "samples",
    "example", "examples", "demo", "demos", "bench", "benchmark", "lib", "libs",
    "vendor", "vendors", "node_modules", "deps", "dep", "third_party", "third-party",
    "artifacts", "out", "cache", "dist", "build",
}

EXCLUDE_NAME_HINTS = {
    "baseaccount", "iaccount", "erc4337", "account", "validator", "module",
    "sample", "example", "mock", "test",
}

ALLOWLIST_FILES = {
    "CoinbaseSmartWallet.sol",
    "SoulWallet.sol",
    "SimpleAccount.sol",
    "MSAAdvanced.sol",
    "uMSAAdvanced.sol",
    "uMSABasic.sol",
}

ACCOUNT_LIKE_HINTS = [
    "smartwallet", "wallet", "account",
]


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def _load_discovery(path: Path) -> dict:
    if not path.exists():
        return {"repos": [], "queries": [], "org_seeds": []}
    return json.loads(path.read_text(encoding="utf-8"))


def _repo_name(rel: Path) -> str:
    return rel.parts[0] if rel.parts else ""


def _is_excluded_by_path(rel: Path) -> tuple[bool, str]:
    lowered = [p.lower() for p in rel.parts[:-1]]
    for p in lowered:
        if p in EXCLUDE_PATH_PARTS:
            return True, f"path-part:{p}"
    return False, ""


def _is_concrete_validate_userop(text: str) -> bool:
    return bool(FUNC_RE.search(text))


def _classify_role(rel: Path, text: str) -> tuple[str, str]:
    name = rel.name
    stem = rel.stem.lower()
    low = text.lower()

    if "abstract contract" in low:
        return "exclude", "abstract-contract"

    if name in ALLOWLIST_FILES:
        return "include", "allowlist-file"

    if not any(h in stem for h in ACCOUNT_LIKE_HINTS):
        return "exclude", "non-account-like-name"

    if stem in EXCLUDE_NAME_HINTS:
        return "exclude", f"name-hint:{stem}"

    if any(tok in low for tok in ["this contract provides the basic logic", "interface of the erc-165", "should never be deployed"]):
        return "exclude", "docstring-nondeployable"

    if any(tok in low for tok in ["upgradeable", "initializer", "onlyentrypoint", "validateuserop", "entrypoint"]):
        return "include", "deployable-heuristic"

    return "review", "manual-review-needed"


def build_dataset(source_root: Path, discovery_path: Path, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    results_dir = out_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    discovery = _load_discovery(discovery_path)
    repo_lookup = {r.get("nameWithOwner", "").split("/")[-1]: r for r in discovery.get("repos", [])}

    included: list[dict] = []
    excluded: list[dict] = []
    review: list[dict] = []
    seen_hashes: dict[str, str] = {}
    dedupe_counter = 0

    for sol in sorted(source_root.rglob("*.sol")):
        if not sol.is_file():
            continue
        rel = sol.relative_to(source_root)
        try:
            text = sol.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if not _is_concrete_validate_userop(text):
            continue

        excluded_by_path, reason = _is_excluded_by_path(rel)
        rec = {
            "file": str(sol),
            "relative_path": str(rel),
            "repo": _repo_name(rel),
            "sha256": _sha256_text(text),
            "reason": reason,
            "source": repo_lookup.get(_repo_name(rel), {}),
        }

        if excluded_by_path:
            excluded.append(rec)
            continue

        role, role_reason = _classify_role(rel, text)
        rec["reason"] = role_reason
        if role == "exclude":
            excluded.append(rec)
            continue
        if role == "review":
            review.append(rec)
            continue

        sha = rec["sha256"]
        if sha in seen_hashes:
            dedupe_counter += 1
            rec["reason"] = f"duplicate-of:{seen_hashes[sha]}"
            excluded.append(rec)
            continue
        seen_hashes[sha] = str(rel)
        included.append(rec)

    manifest = {
        "dataset_name": "aa4337_prevalence_main",
        "description": "Natural-distribution main evaluation set for ERC-4337 validateUserOp prevalence",
        "source_root": str(source_root),
        "discovery_file": str(discovery_path),
        "selection_policy": {
            "must_have": ["concrete validateUserOp implementation", "real open-source source file"],
            "exclude_path_parts": sorted(EXCLUDE_PATH_PARTS),
            "exclude_abstract": True,
            "exclude_vendor_and_generated": True,
            "exclude_test_sample_mock_demo": True,
            "dedupe": "exact source sha256",
        },
        "queries": discovery.get("queries", []),
        "org_seeds": discovery.get("org_seeds", []),
        "count": len(included),
        "contracts": included,
        "stats": {
            "included": len(included),
            "excluded": len(excluded),
            "review": len(review),
            "deduplicated_exact": dedupe_counter,
            "by_repo": dict(Counter(rec["repo"] for rec in included)),
        },
    }

    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (results_dir / "excluded_candidates.json").write_text(json.dumps(excluded, indent=2), encoding="utf-8")
    (results_dir / "review_candidates.json").write_text(json.dumps(review, indent=2), encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build prevalence-oriented ERC-4337 main evaluation dataset")
    parser.add_argument("--source-root", default=str(DEFAULT_SOURCE_ROOT))
    parser.add_argument("--discovery-file", default=str(DEFAULT_DISCOVERY))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    manifest = build_dataset(Path(args.source_root), Path(args.discovery_file), Path(args.out_dir))
    print(json.dumps({
        "dataset": manifest["dataset_name"],
        "count": manifest["count"],
        "manifest": str(Path(args.out_dir) / "manifest.json"),
        "stats": manifest["stats"],
    }, indent=2))


if __name__ == "__main__":
    main()
