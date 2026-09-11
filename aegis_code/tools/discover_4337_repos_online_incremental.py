#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXISTING_MANIFEST = ROOT / "datasets" / "aa4337_full_real" / "manifest.json"
DEFAULT_OUT_DIR = ROOT / "datasets" / "aa4337_full_real" / "discovery"

SEARCH_QUERIES = [
    "ERC-4337 language:Solidity fork:false",
    "EIP-4337 language:Solidity fork:false",
    "UserOperation EntryPoint paymaster language:Solidity fork:false",
    "validateUserOp language:Solidity fork:false",
    "account-abstraction language:Solidity fork:false",
    "topic:erc-4337 language:Solidity fork:false",
    "topic:account-abstraction language:Solidity fork:false",
]

ORG_SEEDS = [
    "eth-infinitism",
    "safe-global",
    "alchemyplatform",
    "zerodevapp",
    "coinbase",
    "pimlicolabs",
    "base",
    "SoulWallet",
    "erc7579",
    "passkeys-4337",
    "gelatodigital",
    "artela-network",
    "stackup-wallet",
    "biconomy",
]

KEYWORDS = [
    "erc-4337",
    "eip-4337",
    "account abstraction",
    "useroperation",
    "entrypoint",
    "paymaster",
    "bundler",
    "validateuserop",
    "erc7579",
]


def _request_json(url: str, token: str | None = None) -> dict:
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "aa4337-discovery")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8", errors="ignore"))


def _repo_record(item: dict, source: str) -> dict:
    return {
        "nameWithOwner": item.get("full_name", ""),
        "url": item.get("html_url", ""),
        "description": item.get("description", "") or "",
        "stargazersCount": int(item.get("stargazers_count", 0) or 0),
        "pushedAt": item.get("pushed_at", ""),
        "isFork": bool(item.get("fork", False)),
        "visibility": "PUBLIC",
        "source": source,
    }


def _is_relevant(rec: dict) -> bool:
    txt = " ".join([
        rec.get("nameWithOwner", ""),
        rec.get("description", ""),
    ]).lower()
    return any(k in txt for k in KEYWORDS)


def _load_existing_repo_names(manifest_path: Path) -> set[str]:
    if not manifest_path.exists():
        return set()
    man = json.loads(manifest_path.read_text(encoding="utf-8"))
    repos = {c.get("repo", "") for c in man.get("contracts", []) if c.get("repo")}
    return repos


def _search_repos(query: str, token: str | None, max_pages: int = 3, per_page: int = 100) -> list[dict]:
    out: list[dict] = []
    for page in range(1, max_pages + 1):
        q = urllib.parse.quote(query)
        url = f"https://api.github.com/search/repositories?q={q}&sort=updated&order=desc&per_page={per_page}&page={page}"
        try:
            data = _request_json(url, token)
        except Exception:
            break
        items = data.get("items", [])
        if not items:
            break
        out.extend(_repo_record(item, f"query:{query}") for item in items)
        time.sleep(0.25)
    return out


def _org_repos(org: str, token: str | None, max_pages: int = 2, per_page: int = 100) -> list[dict]:
    out: list[dict] = []
    for page in range(1, max_pages + 1):
        url = f"https://api.github.com/orgs/{org}/repos?type=public&sort=updated&per_page={per_page}&page={page}"
        try:
            data = _request_json(url, token)
        except Exception:
            break
        if not isinstance(data, list) or not data:
            break
        out.extend(_repo_record(item, f"org:{org}") for item in data)
        time.sleep(0.2)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Online incremental ERC-4337 repository discovery")
    parser.add_argument("--existing-manifest", default=str(DEFAULT_EXISTING_MANIFEST))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument("--max-query-pages", type=int, default=3)
    parser.add_argument("--max-org-pages", type=int, default=2)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")

    existing_repo_names = _load_existing_repo_names(Path(args.existing_manifest))

    discovered: list[dict] = []
    for q in SEARCH_QUERIES:
        discovered.extend(_search_repos(q, token, max_pages=args.max_query_pages))
    for org in ORG_SEEDS:
        discovered.extend(_org_repos(org, token, max_pages=args.max_org_pages))

    dedup: dict[str, dict] = {}
    for rec in discovered:
        full = rec.get("nameWithOwner", "")
        if not full:
            continue
        if full in dedup:
            if len(rec.get("description", "")) > len(dedup[full].get("description", "")):
                dedup[full] = rec
        else:
            dedup[full] = rec

    all_unique = list(dedup.values())
    relevant = [r for r in all_unique if _is_relevant(r)]

    new_relevant = []
    for r in relevant:
        repo_tail = r.get("nameWithOwner", "").split("/")[-1]
        if repo_tail and repo_tail not in existing_repo_names:
            new_relevant.append(r)

    out = {
        "generated_at_epoch": int(time.time()),
        "token_present": bool(token),
        "queries": SEARCH_QUERIES,
        "org_seeds": ORG_SEEDS,
        "existing_repo_names_count": len(existing_repo_names),
        "total_unique_online": len(all_unique),
        "total_relevant_online": len(relevant),
        "new_relevant_count": len(new_relevant),
        "new_relevant_repos": sorted(new_relevant, key=lambda x: x.get("stargazersCount", 0), reverse=True),
    }

    out_file = out_dir / "online_incremental_discovery.json"
    out_file.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps({
        "out": str(out_file),
        "token_present": out["token_present"],
        "total_unique_online": out["total_unique_online"],
        "total_relevant_online": out["total_relevant_online"],
        "new_relevant_count": out["new_relevant_count"],
    }, indent=2))


if __name__ == "__main__":
    main()
