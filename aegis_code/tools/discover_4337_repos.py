#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT_DEFAULT = ROOT / "datasets" / "aa4337_large_prod" / "discovery"


SEARCH_QUERIES = [
    "ERC-4337 language:Solidity stars:>=0 fork:false",
    "EIP-4337 language:Solidity stars:>=0 fork:false",
    "UserOperation EntryPoint paymaster language:Solidity fork:false",
    "account abstraction EntryPoint language:Solidity fork:false",
    "repo:eth-infinitism/account-abstraction",
]

TOPIC_QUERIES = [
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


def _run_gh_search(query: str, limit: int) -> list[dict]:
    cmd = [
        "gh",
        "search",
        "repos",
        query,
        "--limit",
        str(limit),
        "--json",
        "nameWithOwner,url,description,stargazersCount,pushedAt,isFork,visibility",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return []
    if proc.returncode != 0:
        return []
    try:
        data = json.loads(proc.stdout)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def _run_gh_org(org: str, limit: int) -> list[dict]:
    cmd = [
        "gh",
        "repo",
        "list",
        org,
        "--limit",
        str(limit),
        "--json",
        "nameWithOwner,url,description,stargazerCount,pushedAt,isFork,visibility,primaryLanguage",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return []
    if proc.returncode != 0:
        return []
    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    out = []
    for r in raw if isinstance(raw, list) else []:
        out.append(
            {
                "nameWithOwner": r.get("nameWithOwner"),
                "url": r.get("url"),
                "description": r.get("description"),
                "stargazersCount": r.get("stargazerCount", 0),
                "pushedAt": r.get("pushedAt"),
                "isFork": r.get("isFork", False),
                "visibility": r.get("visibility", "UNKNOWN"),
                "source": f"org:{org}",
            }
        )
    return out


def _is_4337_relevant(repo: dict) -> bool:
    txt = f"{repo.get('nameWithOwner','')} {repo.get('description','') or ''}".lower()
    keys = [
        "4337",
        "account abstraction",
        "account-abstraction",
        "useroperation",
        "entrypoint",
        "paymaster",
        "smart wallet",
        "smart-wallet",
        "erc7579",
    ]
    return any(k in txt for k in keys)


def main() -> None:
    parser = argparse.ArgumentParser(description="Discover ERC-4337 repositories from GitHub")
    parser.add_argument("--out-dir", default=str(OUT_DEFAULT))
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []

    for q in SEARCH_QUERIES + TOPIC_QUERIES:
        got = _run_gh_search(q, args.limit)
        for g in got:
            g["source"] = f"search:{q}"
            rows.append(g)

    for org in ORG_SEEDS:
        rows.extend(_run_gh_org(org, args.limit))

    dedup = {}
    for r in rows:
        name = r.get("nameWithOwner")
        if not name:
            continue
        if name not in dedup:
            dedup[name] = r
        else:
            prev_src = dedup[name].get("source", "")
            curr_src = r.get("source", "")
            dedup[name]["source"] = f"{prev_src};{curr_src}" if curr_src and curr_src not in prev_src else prev_src

    all_repos = list(dedup.values())
    relevant = [r for r in all_repos if _is_4337_relevant(r)]

    payload = {
        "queries": SEARCH_QUERIES + TOPIC_QUERIES,
        "org_seeds": ORG_SEEDS,
        "total_raw": len(rows),
        "total_unique": len(all_repos),
        "total_relevant": len(relevant),
        "repos": sorted(relevant, key=lambda x: (x.get("stargazersCount", 0), x.get("nameWithOwner", "")), reverse=True),
        "note": "Discovery requires GitHub CLI authentication for full coverage.",
        "gh_token_present": bool(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")),
        "gh_available": shutil.which("gh") is not None,
    }

    out_file = out_dir / "discovered_repos.json"
    out_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({
        "out": str(out_file),
        "total_unique": payload["total_unique"],
        "total_relevant": payload["total_relevant"],
        "gh_token_present": payload["gh_token_present"],
    }, indent=2))


if __name__ == "__main__":
    main()
