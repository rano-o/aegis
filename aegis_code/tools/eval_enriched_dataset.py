#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
from collections import deque
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANALYZER = ROOT / "src" / "aa4337_analyzer.py"
SOLC_DEFAULT = "/Users/chenting/.solc-select/artifacts/solc-0.8.28/solc-0.8.28"


def _remap_target(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def _parse_solc_args(solc_args: str) -> tuple[list[str], set[str], list[str]]:
    parts = shlex.split(solc_args)
    include_paths: list[str] = []
    allow_paths: set[str] = set()
    extra: list[str] = []
    i = 0
    while i < len(parts):
        if parts[i] == "--include-path" and i + 1 < len(parts):
            include_paths.append(parts[i + 1])
            i += 2
            continue
        if parts[i] == "--allow-paths" and i + 1 < len(parts):
            allow_paths.update(x for x in parts[i + 1].split(",") if x)
            i += 2
            continue
        extra.append(parts[i])
        i += 1
    return include_paths, allow_paths, extra


def _format_solc_args(
    include_paths: list[str], allow_paths: set[str], extra: list[str]
) -> str:
    tokens = [str(x) for x in extra]
    for p in sorted(set(include_paths)):
        tokens.extend(["--include-path", str(p)])
    if allow_paths:
        tokens.extend(["--allow-paths", ",".join(sorted(str(x) for x in allow_paths))])
    return " ".join(shlex.quote(tok) for tok in tokens).strip()


def _parse_remaps(remaps: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for tok in shlex.split(remaps):
        if "=" in tok:
            k, v = tok.split("=", 1)
            out[k] = v
    return out


def _format_remaps(remap_pairs: dict[str, str]) -> str:
    return " ".join(
        shlex.quote(f"{k}={v}")
        for k, v in sorted(
            remap_pairs.items(), key=lambda item: len(item[0]), reverse=True
        )
    )


def _repo_root_for(source_file: Path, src_root: Path) -> Path:
    cur = source_file.parent
    while cur != cur.parent:
        if (
            (cur / "foundry.toml").exists()
            or (cur / "hardhat.config.ts").exists()
            or (cur / "hardhat.config.js").exists()
        ):
            return cur
        if cur.parent == src_root:
            return cur
        cur = cur.parent
    return source_file.parent


def _prefer_repo_local_dependency_roots(
    source_file: Path, src_root: Path
) -> dict[str, Path]:
    repo_root = _repo_root_for(source_file, src_root)
    candidates: dict[str, Path] = {}

    def _choose_best(paths: list[Path], prefer_subpath: str = "") -> Path | None:
        if not paths:
            return None

        def _score(p: Path) -> tuple[int, int, int, int]:
            s = p.as_posix().lower()
            avoid_hits = sum(
                1
                for token in ["/test/", "/tests/", "/node_modules/", "/vendor/"]
                if token in s
            )
            prefer_miss = 0 if (prefer_subpath and prefer_subpath in s) else 1
            try:
                rel_depth = len(p.relative_to(repo_root).parts)
            except Exception:
                rel_depth = len(p.parts)
            return (avoid_hits, prefer_miss, rel_depth, len(s))

        return sorted(paths, key=_score)[0]

    aa_matches = sorted(
        repo_root.rglob("**/account-abstraction/contracts/interfaces/IAccount.sol")
    )
    if aa_matches:
        best = _choose_best(
            aa_matches, "/lib/account-abstraction/contracts/interfaces/"
        )
        aa_root = (best or aa_matches[0]).parents[2]
        candidates["@account-abstraction/contracts/"] = aa_root / "contracts"
        candidates["@eth-infinitism/account-abstraction/"] = aa_root / "contracts"

    oz_matches = sorted(
        repo_root.rglob(
            "**/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol"
        )
    )
    if oz_matches:
        best = _choose_best(oz_matches, "/lib/openzeppelin-contracts/contracts/")
        oz_root = (best or oz_matches[0]).parents[3]
        candidates["@openzeppelin/contracts/"] = oz_root / "contracts"
        candidates["@openzeppelin/"] = oz_root

    return {k: v for k, v in candidates.items() if v.exists()}


def _resolve_import_path(
    import_path: str, source_file: Path, src_root: Path
) -> Path | None:
    repo_root = _repo_root_for(source_file, src_root)

    def _repo_first(glob_rel: str) -> Path | None:
        for c in repo_root.rglob(glob_rel):
            if c.is_file() and c.suffix == ".sol":
                return c.resolve()
        for c in src_root.rglob(glob_rel):
            if c.is_file() and c.suffix == ".sol":
                return c.resolve()
        return None

    if import_path.startswith("."):
        q = source_file.parent / import_path
        if q.suffix != ".sol":
            q = q.with_suffix(".sol")
        return q.resolve() if q.exists() else None

    if import_path.startswith("@openzeppelin/contracts/"):
        rest = import_path[len("@openzeppelin/contracts/") :]
        m = _repo_first(f"openzeppelin-contracts/contracts/{rest}")
        if m is not None:
            return m
    if import_path.startswith("@account-abstraction/contracts/"):
        rest = import_path[len("@account-abstraction/contracts/") :]
        m = _repo_first(f"account-abstraction/contracts/{rest}")
        if m is not None:
            return m
    if import_path.startswith("solady/"):
        rest = import_path[len("solady/") :]
        m = _repo_first(f"solady/src/{rest}")
        if m is not None:
            return m
    if import_path.startswith("@solady/"):
        rest = import_path[len("@solady/") :]
        m = _repo_first(f"solady/src/{rest}")
        if m is not None:
            return m

    q = src_root / import_path
    if q.suffix != ".sol":
        q = q.with_suffix(".sol")
    if q.exists():
        return q.resolve()
    if import_path.startswith("@"):
        parts = import_path.split("/")
        if len(parts) >= 3:
            rest = "/".join(parts[2:])
            for c in src_root.rglob(rest):
                if c.is_file() and c.suffix == ".sol":
                    return c.resolve()
    name = Path(import_path).name
    for c in src_root.rglob(name):
        if c.is_file() and c.suffix == ".sol":
            return c.resolve()
    return None


def _add_alias_remap(
    import_path: str, target_file: Path, remap_pairs: dict[str, str]
) -> None:
    parts = import_path.split("/")
    if import_path.startswith("@") and len(parts) >= 3:
        prefix = "/".join(parts[:2]) + "/"
        rest = parts[2:]
    elif len(parts) >= 2:
        prefix = parts[0] + "/"
        rest = parts[1:]
    else:
        return
    if prefix in remap_pairs:
        return
    anc = target_file
    for _ in range(len(rest)):
        anc = anc.parent
    remap_pairs[prefix] = _remap_target(anc) + "/"


_IMPORT_RE = re.compile(
    r"import\s+(?:[^\"']+from\s+)?[\"']([^\"']+)[\"']\s*;", re.IGNORECASE
)


def _seed_import_closure(
    source_file: Path,
    src_root: Path,
    include_paths: list[str],
    allow_paths: set[str],
    remap_pairs: dict[str, str],
    max_files: int = 160,
) -> None:
    visited: set[Path] = set()
    q: deque[Path] = deque([source_file])
    while q and len(visited) < max_files:
        cur = q.popleft()
        if cur in visited or not cur.exists():
            continue
        visited.add(cur)
        try:
            text = cur.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for imp in _IMPORT_RE.findall(text):
            resolved = _resolve_import_path(imp, cur, src_root)
            if resolved is None:
                continue
            include_paths.append(str(resolved.parent))
            allow_paths.add(str(resolved.parent))
            if (not imp.startswith(".")) and (imp.startswith("@") or "/" in imp):
                _add_alias_remap(imp, resolved, remap_pairs)
            if resolved not in visited:
                q.append(resolved)


def build_solc_args_and_remaps(source_file: Path, src_root: Path) -> tuple[str, str]:
    include_paths = {
        src_root,
        ROOT / "datasets" / "aa4337_large_prod" / "contracts",
    }
    oz_root = src_root / "openzeppelin-compat"
    gnosis_root = src_root / "gnosis-safe-compat"
    extra_args: list[str] = []
    if "entrypoint-hash-poc" in str(source_file):
        oz_root = src_root / "entrypoint-hash-poc" / "lib" / "openzeppelin-contracts"
        extra_args.extend(["--via-ir", "--optimize"])
    elif "alto/contracts/lib/account-abstraction-v6/" in str(source_file):
        oz_root = (
            src_root / "alto" / "contracts" / "lib" / "openzeppelin-contracts-v4.8.3"
        )
    elif "alto/contracts/lib/singleton-paymaster/lib/account-abstraction-v6/" in str(
        source_file
    ):
        oz_root = (
            src_root
            / "alto"
            / "contracts"
            / "lib"
            / "singleton-paymaster"
            / "lib"
            / "openzeppelin-contracts-v4.8.3"
        )
    elif "base-paymaster/lib/account-abstraction/" in str(source_file):
        oz_root = src_root / "base-paymaster" / "lib" / "openzeppelin-contracts"
    elif "erc20-paymaster/lib/account-abstraction-v6/" in str(source_file):
        oz_root = src_root / "erc20-paymaster" / "lib" / "openzeppelin-contracts-v4.8.0"
    elif "passkeys-smart-wallet/contracts/lib/account-abstraction/" in str(source_file):
        oz_root = (
            src_root
            / "passkeys-smart-wallet"
            / "contracts"
            / "lib"
            / "openzeppelin-contracts"
        )
    elif "singleton-paymaster/lib/account-abstraction-v6/" in str(source_file):
        oz_root = (
            src_root / "singleton-paymaster" / "lib" / "openzeppelin-contracts-v4.8.3"
        )
    elif (
        "modular-account/lib/light-account/lib/modular-account/lib/light-account/lib/account-abstraction/"
        in str(source_file)
    ):
        oz_root = (
            src_root
            / "modular-account"
            / "lib"
            / "light-account"
            / "lib"
            / "modular-account"
            / "lib"
            / "light-account"
            / "lib"
            / "openzeppelin-contracts"
        )
    elif (
        "modular-account/lib/light-account/lib/modular-account/lib/account-abstraction/"
        in str(source_file)
    ):
        oz_root = (
            src_root
            / "modular-account"
            / "lib"
            / "light-account"
            / "lib"
            / "modular-account"
            / "lib"
            / "openzeppelin-contracts"
        )
    elif "rundler/crates/contracts/contracts/v0_6/lib/account-abstraction/" in str(
        source_file
    ):
        oz_root = (
            src_root
            / "rundler"
            / "crates"
            / "contracts"
            / "contracts"
            / "v0_6"
            / "lib"
            / "openzeppelin-contracts"
        )
    elif "smart-wallet/lib/account-abstraction/" in str(source_file):
        oz_root = src_root / "smart-wallet" / "lib" / "openzeppelin-contracts"
    remap_pairs = {
        "@openzeppelin/contracts/security/": oz_root / "contracts" / "security",
        "@openzeppelin/contracts/": oz_root / "contracts",
        "@openzeppelin/": oz_root,
        "@uniswap/v3-core/contracts/": src_root / "uniswap-v3-core" / "contracts",
        "@uniswap/v3-periphery/contracts/": src_root
        / "uniswap-v3-periphery"
        / "contracts",
        "@account-abstraction/contracts/": src_root
        / "account-abstraction"
        / "contracts",
        "@eth-infinitism/account-abstraction/": src_root
        / "entrypoint-hash-poc"
        / "lib"
        / "account-abstraction"
        / "contracts",
        "@gnosis.pm/safe-contracts/contracts/": gnosis_root / "contracts",
    }

    remap_pairs.update(_prefer_repo_local_dependency_roots(source_file, src_root))
    include_paths.update(remap_pairs.values())

    parts = source_file.parts
    path_str = str(source_file)
    if "account-abstraction" in parts:
        repo_root = source_file
        while repo_root != repo_root.parent and repo_root.name != "account-abstraction":
            repo_root = repo_root.parent
        include_paths.add(repo_root)
        include_paths.add(repo_root / "contracts")
    if "artela-account-abstraction" in parts:
        repo_root = source_file
        while (
            repo_root != repo_root.parent
            and repo_root.name != "artela-account-abstraction"
        ):
            repo_root = repo_root.parent
        include_paths.add(repo_root)
        include_paths.add(repo_root / "contracts")
        extra_args.extend(["--via-ir", "--optimize"])
    if "erc4337-contracts-v07" in parts:
        repo_root = source_file
        while (
            repo_root != repo_root.parent and repo_root.name != "erc4337-contracts-v07"
        ):
            repo_root = repo_root.parent
        include_paths.add(repo_root)
        include_paths.add(repo_root / "contracts")
    if any(
        seg in path_str
        for seg in [
            "alto/",
            "erc20-paymaster/",
            "singleton-paymaster/",
            "smart-wallet/",
        ]
    ):
        repo_root = source_file.parent
        while (
            repo_root != repo_root.parent and not (repo_root / "foundry.toml").exists()
        ):
            repo_root = repo_root.parent
        include_paths.add(repo_root)
        include_paths.add(repo_root / "src")
        include_paths.add(repo_root / "contracts")
        include_paths.add(repo_root / "lib")
    if "aa-benchmark" in parts:
        repo_root = source_file
        while repo_root != repo_root.parent and repo_root.name != "aa-benchmark":
            repo_root = repo_root.parent
        include_paths.add(repo_root)
        include_paths.add(repo_root / "src")
        include_paths.add(repo_root / "test")
        include_paths.add(repo_root / "script")
        include_paths.add(repo_root / "lib")
        remap_pairs["forge-std/"] = repo_root / "lib" / "forge-std" / "src"
        remap_pairs["I4337/"] = repo_root / "lib" / "I4337" / "src"
        remap_pairs["solady/"] = repo_root / "lib" / "solady" / "src"
        remap_pairs["src/"] = repo_root / "src"
        remap_pairs["test/"] = repo_root / "test"
        remap_pairs["script/"] = repo_root / "script"
    if "rundler/crates/contracts/contracts" in path_str:
        repo_root = source_file
        while repo_root != repo_root.parent and repo_root.name != "contracts":
            repo_root = repo_root.parent
        include_paths.add(repo_root)
        include_paths.add(repo_root / "v0_8")
        include_paths.add(repo_root / "v0_9")

    include_paths.update(remap_pairs.values())

    allow_paths = {
        str(ROOT),
        *(str(p) for p in include_paths),
        *(_remap_target(v) for v in remap_pairs.values()),
    }
    solc_args = _format_solc_args(
        [str(p) for p in include_paths],
        allow_paths,
        [*extra_args, "--base-path", str(ROOT)],
    )
    remaps = _format_remaps(
        {
            k: _remap_target(v) + "/"
            for k, v in sorted(
                remap_pairs.items(), key=lambda item: len(item[0]), reverse=True
            )
        }
    )
    return solc_args, remaps


def run_one(
    python_bin: str,
    solc: str,
    source_file: Path,
    result_file: Path,
    solc_args: str,
    remaps: str,
    src_root: Path | None = None,
) -> dict:
    solc_candidates = [solc]
    solc_fallback = "/Users/chenting/.solc-select/artifacts/solc-0.8.20/solc-0.8.20"
    if solc != solc_fallback and Path(solc_fallback).exists():
        solc_candidates.append(solc_fallback)

    include_paths, allow_paths, extra = _parse_solc_args(solc_args)
    remap_pairs = _parse_remaps(remaps)
    if src_root is not None:
        repo_root = _repo_root_for(source_file, src_root)
        include_paths.extend([str(src_root), str(repo_root)])
        for seg in ["src", "contracts", "lib", "modules", "packages"]:
            q = repo_root / seg
            if q.exists():
                include_paths.append(str(q))
        _seed_import_closure(
            source_file, src_root, include_paths, allow_paths, remap_pairs
        )
    allow_paths.add(str(ROOT))
    allow_paths.update(include_paths)

    missing_src_re = re.compile(r'Source\s+"([^"]+)"\s+not\s+found', re.IGNORECASE)
    pragma_re = re.compile(r"requires different compiler version", re.IGNORECASE)

    best_proc = None
    best_out = result_file
    solc_idx = 0
    for attempt in range(7):
        out = (
            result_file
            if attempt == 0
            else result_file.with_name(
                result_file.stem + f".retry{attempt}" + result_file.suffix
            )
        )
        cur_solc = solc_candidates[min(solc_idx, len(solc_candidates) - 1)]
        cmd = [
            python_bin,
            str(ANALYZER),
            str(source_file),
            "--solc",
            cur_solc,
            "--solc-args",
            _format_solc_args(include_paths, allow_paths, extra),
            "--solc-remaps",
            _format_remaps(remap_pairs),
            "--json-out",
            str(out),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT))
        best_proc = proc
        best_out = out
        if proc.returncode == 0 and out.exists():
            break
        changed = False
        stderr = proc.stderr or ""
        for imp in missing_src_re.findall(stderr):
            if src_root is None:
                continue
            resolved = _resolve_import_path(imp, source_file, src_root)
            if resolved is None:
                continue
            include_paths.append(str(resolved.parent))
            allow_paths.add(str(resolved.parent))
            if (not imp.startswith(".")) and (imp.startswith("@") or "/" in imp):
                _add_alias_remap(imp, resolved, remap_pairs)
            changed = True
        if (
            not changed
            and pragma_re.search(stderr)
            and solc_idx + 1 < len(solc_candidates)
        ):
            solc_idx += 1
            changed = True
        if not changed:
            break

    proc = best_proc
    result_file = best_out
    rec = {
        "file": str(source_file),
        "exit_code": proc.returncode if proc is not None else 1,
        "stdout": (proc.stdout[-1000:] if proc is not None else ""),
        "stderr": (proc.stderr[-1000:] if proc is not None else ""),
        "result_file": str(result_file),
        "total_findings": 0,
        "summary": {},
    }
    if result_file.exists() and rec["exit_code"] == 0:
        payload = json.loads(result_file.read_text(encoding="utf-8"))
        rec["total_findings"] = payload.get("total_findings", 0)
        rec["summary"] = payload.get("summary", {})
    return rec


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate analyzer on real vuln-enriched 4337 dataset"
    )
    parser.add_argument("--dataset-dir", required=True)
    parser.add_argument("--python-bin", default=str(ROOT / ".venv" / "bin" / "python"))
    parser.add_argument("--solc", default=SOLC_DEFAULT)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    ds = Path(args.dataset_dir)
    manifest = json.loads((ds / "manifest.json").read_text(encoding="utf-8"))
    contracts = manifest["contracts"]
    if args.limit > 0:
        contracts = contracts[: args.limit]

    results_dir = ds / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    src_root = Path(manifest["source_root"])
    details = []
    rc = Counter()
    ok = fail = with_find = total_findings = 0
    for c in contracts:
        src = Path(c["source_file"])
        out = results_dir / (src.name + "." + str(abs(hash(str(src)))) + ".json")
        solc_args, remaps = build_solc_args_and_remaps(src, src_root)
        rec = run_one(args.python_bin, args.solc, src, out, solc_args, remaps, src_root)
        details.append(rec)
        if rec["exit_code"] == 0:
            ok += 1
        else:
            fail += 1
        if rec["total_findings"] > 0:
            with_find += 1
        total_findings += rec["total_findings"]
        for k, v in rec["summary"].items():
            rc[k] += int(v)

    summary = {
        "dataset": manifest["dataset_name"],
        "contracts_total": len(contracts),
        "contracts_ok": ok,
        "contracts_failed": fail,
        "contracts_with_findings": with_find,
        "total_findings": total_findings,
        "findings_by_rule": dict(rc),
    }
    (results_dir / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    (results_dir / "details.json").write_text(
        json.dumps(details, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
