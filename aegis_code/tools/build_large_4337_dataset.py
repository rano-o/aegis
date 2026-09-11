#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "datasets" / "aa4337_large"


@dataclass
class RepoSpec:
    url: str
    name: str


DEFAULT_REPOS: list[RepoSpec] = [
    RepoSpec("https://github.com/eth-infinitism/account-abstraction.git", "account-abstraction"),
    RepoSpec("https://github.com/safe-global/safe-smart-account.git", "safe-smart-account"),
    RepoSpec("https://github.com/alchemyplatform/modular-account.git", "modular-account"),
    RepoSpec("https://github.com/zerodevapp/kernel.git", "kernel"),
    RepoSpec("https://github.com/biconomy/scw-contracts.git", "scw-contracts"),
    RepoSpec("https://github.com/pimlicolabs/erc20-paymaster.git", "erc20-paymaster"),
    RepoSpec("https://github.com/stackup-wallet/stackup.git", "stackup"),
    RepoSpec("https://github.com/candidelabs/voltaire.git", "voltaire"),
    RepoSpec("https://github.com/OpenZeppelin/openzeppelin-contracts.git", "openzeppelin-contracts"),
    RepoSpec("https://github.com/Uniswap/v3-periphery.git", "uniswap-v3-periphery"),
    RepoSpec("https://github.com/Uniswap/v3-core.git", "uniswap-v3-core"),
    RepoSpec("https://github.com/coinbase/smart-wallet.git", "smart-wallet"),
    RepoSpec("https://github.com/SoulWallet/soul-wallet-contract.git", "soul-wallet-contract"),
    RepoSpec("https://github.com/safe-global/safe-modules.git", "safe-modules"),
    RepoSpec("https://github.com/stackup-wallet/contracts.git", "stackup-contracts"),
    RepoSpec("https://github.com/base/paymaster.git", "base-paymaster"),
    RepoSpec("https://github.com/coinbase/verifying-paymaster.git", "verifying-paymaster"),
    RepoSpec("https://github.com/ithacaxyz/account.git", "ithaca-account"),
    RepoSpec("https://github.com/erc7579/erc7579-implementation.git", "erc7579-implementation"),
    RepoSpec("https://github.com/passkeys-4337/smart-wallet.git", "passkeys-smart-wallet"),
    RepoSpec("https://github.com/gelatodigital/erc4337-contracts-v07.git", "erc4337-contracts-v07"),
    RepoSpec("https://github.com/artela-network/account-abstraction.git", "artela-account-abstraction"),
    RepoSpec("https://github.com/eth-infinitism/account-abstraction-samples.git", "account-abstraction-samples"),
]


def _run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def _safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _clone_repo(repo: RepoSpec, dst_dir: Path) -> dict:
    code, out, err = _run(["git", "clone", "--depth", "1", repo.url, str(dst_dir / repo.name)])
    return {
        "repo": repo.url,
        "name": repo.name,
        "ok": code == 0,
        "stdout": out[-1000:],
        "stderr": err[-1000:],
        "path": str(dst_dir / repo.name),
    }


def _iter_sol_files(path: Path) -> Iterable[Path]:
    yield from path.rglob("*.sol")


def _is_prod_contract_path(relpath: str) -> bool:
    rp = relpath.lower()
    parts = [p for p in rp.split("/") if p]
    noisy_names = {"test", "tests", "script", "scripts", "gas", "mock", "mocks", "bench", "benchmark"}
    if any(p in noisy_names for p in parts):
        return False
    if rp.startswith("test/") or rp.startswith("tests/") or rp.startswith("script/") or rp.startswith("scripts/"):
        return False
    return True


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
    ]
    return any(k in t for k in indicators) or any(k in rp for k in ["entrypoint", "paymaster", "useroperation", "4337"])


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def build_dataset(out_dir: Path, max_files: int = 2000, cleanup: bool = False, include_tests: bool = False) -> dict:
    _safe_mkdir(out_dir)
    source_dir = out_dir / "sources"
    contracts_dir = out_dir / "contracts"
    _safe_mkdir(source_dir)
    _safe_mkdir(contracts_dir)

    clone_logs = []
    for repo in DEFAULT_REPOS:
        dst = source_dir / repo.name
        if dst.exists():
            clone_logs.append({"repo": repo.url, "name": repo.name, "ok": True, "path": str(dst), "stdout": "already exists", "stderr": ""})
            continue
        clone_logs.append(_clone_repo(repo, source_dir))

    kept = []
    seen_hashes: dict[str, dict] = {}
    skipped_non4337 = 0
    skipped_dupe = 0

    for cl in clone_logs:
        if not cl["ok"]:
            continue
        repo_root = Path(cl["path"])
        repo_name = cl["name"]
        for sol in _iter_sol_files(repo_root):
            if len(kept) >= max_files:
                break
            try:
                text = sol.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            relpath = str(sol.relative_to(repo_root))
            if not include_tests and not _is_prod_contract_path(relpath):
                continue
            if not _is_4337_related(text, relpath):
                skipped_non4337 += 1
                continue
            h = _sha256_text(text)
            if h in seen_hashes:
                skipped_dupe += 1
                continue
            seen_hashes[h] = {"repo": repo_name, "path": relpath}
            target = contracts_dir / repo_name / relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            kept.append(
                {
                    "repo": repo_name,
                    "source_path": relpath,
                    "dataset_path": str(target.relative_to(out_dir)),
                    "sha256": h,
                    "lines": text.count("\n") + 1,
                    "bytes": len(text.encode("utf-8", errors="ignore")),
                }
            )

    if cleanup:
        for cl in clone_logs:
            p = Path(cl["path"])
            if p.exists() and p.is_dir():
                shutil.rmtree(p)

    summary = {
        "dataset_name": "aa4337_large",
        "description": "Large-scale real ERC-4337-related Solidity dataset",
        "repo_candidates": [r.__dict__ for r in DEFAULT_REPOS],
        "clone_logs": clone_logs,
        "total_repos_ok": sum(1 for c in clone_logs if c["ok"]),
        "total_repos_failed": sum(1 for c in clone_logs if not c["ok"]),
        "total_contracts": len(kept),
        "include_tests": include_tests,
        "skipped_non_4337": skipped_non4337,
        "skipped_duplicates": skipped_dupe,
        "contracts": kept,
    }
    (out_dir / "manifest.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Build large-scale ERC-4337 Solidity dataset")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT), help="Output dataset directory")
    parser.add_argument("--max-files", type=int, default=2000, help="Max contracts to keep")
    parser.add_argument("--cleanup", action="store_true", help="Remove cloned source repos after build")
    parser.add_argument("--include-tests", action="store_true", help="Include test/script/mock/gas contracts")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    summary = build_dataset(out_dir=out_dir, max_files=args.max_files, cleanup=args.cleanup, include_tests=args.include_tests)
    print(json.dumps({
        "dataset": summary["dataset_name"],
        "repos_ok": summary["total_repos_ok"],
        "repos_failed": summary["total_repos_failed"],
        "contracts": summary["total_contracts"],
        "manifest": str((out_dir / 'manifest.json')),
    }, indent=2))


if __name__ == "__main__":
    main()
