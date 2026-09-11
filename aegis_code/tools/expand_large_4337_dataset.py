#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def _run(cmd: list[str]) -> tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def _repo_name_from_full(full: str) -> str:
    return full.split("/")[-1]


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def _is_4337_related(content: str, relpath: str) -> bool:
    t = content.lower()
    rp = relpath.lower()
    indicators = [
        "erc-4337",
        "eip-4337",
        "useroperation",
        "packeduseroperation",
        "entrypoint",
        "paymaster",
        "validateuserop",
        "validatepaymasteruserop",
        "iaccount",
        "ipaymaster",
        "getuserophash",
        "account abstraction",
        "erc7579",
    ]
    return any(k in t for k in indicators) or any(k in rp for k in ["entrypoint", "paymaster", "useroperation", "4337", "erc7579"])


def _is_prod_contract_path(relpath: str) -> bool:
    rp = relpath.lower()
    parts = [p for p in rp.split("/") if p]
    noisy_names = {"test", "tests", "script", "scripts", "gas", "mock", "mocks", "bench", "benchmark", "docs", "doc"}
    if any(p in noisy_names for p in parts):
        return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Expand existing large ERC-4337 dataset with missing repositories")
    parser.add_argument("--dataset-dir", required=True)
    parser.add_argument("--coverage-audit", required=True)
    parser.add_argument("--max-repos", type=int, default=50)
    parser.add_argument("--gh-token", default="")
    args = parser.parse_args()

    ds = Path(args.dataset_dir)
    manifest_path = ds / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cov = json.loads(Path(args.coverage_audit).read_text(encoding="utf-8"))

    missing = cov.get("missing_repos", [])
    selected = []
    for r in missing:
        low = r.lower()
        if any(k in low for k in ["docs", "sdk", "demo", "tutorial", "stats", "github.io", "migration", "quickstart", ".github"]):
            continue
        selected.append(r)
    selected = selected[: args.max_repos]

    source_dir = ds / "sources"
    contracts_dir = ds / "contracts"
    source_dir.mkdir(parents=True, exist_ok=True)
    contracts_dir.mkdir(parents=True, exist_ok=True)

    existing_hashes = {c["sha256"] for c in manifest.get("contracts", [])}
    existing_repo_urls = {x["repo"] for x in manifest.get("clone_logs", [])}
    clone_logs = manifest.get("clone_logs", [])
    contracts = manifest.get("contracts", [])

    env = None
    if args.gh_token:
        env = {"GH_TOKEN": args.gh_token}

    added_contracts = 0
    added_repos = 0
    for full in selected:
        repo_url = f"https://github.com/{full}.git"
        repo_name = _repo_name_from_full(full)
        dst = source_dir / repo_name

        if repo_url in existing_repo_urls or dst.exists():
            continue

        cmd = ["git", "clone", "--depth", "1", repo_url, str(dst)]
        p = subprocess.run(cmd, capture_output=True, text=True, env=env)
        ok = p.returncode == 0
        clone_logs.append(
            {
                "repo": repo_url,
                "name": repo_name,
                "ok": ok,
                "stdout": p.stdout[-1000:],
                "stderr": p.stderr[-1000:],
                "path": str(dst),
            }
        )
        if not ok:
            continue

        added_repos += 1
        for sol in dst.rglob("*.sol"):
            relpath = str(sol.relative_to(dst))
            if not _is_prod_contract_path(relpath):
                continue
            try:
                text = sol.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if not _is_4337_related(text, relpath):
                continue
            h = _sha256_text(text)
            if h in existing_hashes:
                continue
            existing_hashes.add(h)
            target = contracts_dir / repo_name / relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            contracts.append(
                {
                    "repo": repo_name,
                    "source_path": relpath,
                    "dataset_path": str(target.relative_to(ds)),
                    "sha256": h,
                    "lines": text.count("\n") + 1,
                    "bytes": len(text.encode("utf-8", errors="ignore")),
                }
            )
            added_contracts += 1

    manifest["clone_logs"] = clone_logs
    manifest["contracts"] = contracts
    manifest["total_repos_ok"] = sum(1 for c in clone_logs if c.get("ok"))
    manifest["total_repos_failed"] = sum(1 for c in clone_logs if not c.get("ok"))
    manifest["total_contracts"] = len(contracts)
    manifest["expansion"] = {
        "selected_missing_repos": selected,
        "added_repos": added_repos,
        "added_contracts": added_contracts,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(
        json.dumps(
            {
                "selected_missing": len(selected),
                "added_repos": added_repos,
                "added_contracts": added_contracts,
                "total_repos_ok": manifest["total_repos_ok"],
                "total_contracts": manifest["total_contracts"],
                "manifest": str(manifest_path),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
