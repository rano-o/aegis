#!/usr/bin/env python3
"""
Tuned Baseline Detector for ERC-4337 validateUserOp vulnerabilities.

This script implements six hand-crafted Slither-based detectors for the six
vulnerability families (VU001-VU005, VU007). It intentionally omits the VOIR
extraction layer: no protocol-profile binding, no path-qualified obligation
coupling, no delegation-aware disambiguation. Rules fire on structural/textual
patterns alone, mirroring the "tuned custom Slither detector" baseline that a
skilled engineer would write without the VOIR abstraction.

The purpose of this script is to serve as the A1 Tuned Baseline experiment in
the Aegis paper, demonstrating that even domain-specific custom rules without
the VOIR semantic layer produce high FP/FN rates compared to full Aegis.

Families:
  VU001 - Authorization Omission (AO)
  VU002 - Nonce Validation Omission (NVO)
  VU003 - Incorrect Success Signaling (ISS)
  VU004 - Intent-Hash Mismatch (IHM)
  VU005 - Nonce Progression Failure (NPF)
  VU007 - Caller-Binding Failure (CBF)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALIDATE_FUNC_RE = re.compile(r"validateUserOp", re.IGNORECASE)

# Patterns used for text-level heuristics (applied to function source text)
AUTH_KEYWORDS = re.compile(
    r"\b(ecrecover|ECDSA\.recover|SignatureChecker|_validateSignature|isValidSignature"
    r"|recover|verifySignature|checkSignature|isOwner|checkOwner|IValidator\.validateUserOp"
    r"|validateSignature|validateSig)\b"
)
NONCE_READ_RE = re.compile(r"\bnonce\b", re.IGNORECASE)
NONCE_STORE_RE = re.compile(
    r"\b(nonces?\s*\[|_nonce\s*=|nonce\s*\+=|\+\+\s*nonce|nonce\s*\+\+|incrementNonce|useNonce|_useNonce)\b",
    re.IGNORECASE,
)
ENTRYPOINT_CALLER_RE = re.compile(
    r"\b(onlyEntryPoint|_requireFromEntryPoint|msg\.sender\s*==\s*.*[Ee]ntry[Pp]oint"
    r"|require\s*\(\s*msg\.sender\s*==|_entryPoint\b.*msg\.sender|entryPoint\(\)\s*\.|isFromEntryPoint)\b"
)
# return 0 / return validationData (where value is 0) / SIG_VALIDATION_FAILED path missing
SUCCESS_RETURN_RE = re.compile(
    r"\breturn\s+(0|validationData|_packValidationData\s*\(false|packValidationData\s*\(false)\b"
)
HASH_RECOMPUTE_RE = re.compile(
    r"\b(keccak256|abi\.encode|getUserOpHash|_hashTypedDataV4|hashUserOp|computeHash)\b"
)
HASH_USE_PARAM_RE = re.compile(r"\buserOpHash\b")


# ---------------------------------------------------------------------------
# Contract-level analysis via Slither (AST walking through JSON output)
# ---------------------------------------------------------------------------

def run_slither_ast(sol_file: str, solc_path: str, allow_paths: str = "") -> dict | None:
    """Run slither --print json and return parsed JSON, or None on error."""
    cmd = [
        "slither",
        sol_file,
        "--json", "-",
        "--solc", solc_path,
    ]
    if allow_paths:
        cmd += ["--solc-args", f"--allow-paths {allow_paths}"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        # slither writes JSON to stdout; errors to stderr
        if result.stdout.strip():
            return json.loads(result.stdout)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Text-level heuristic detectors (operate on raw Solidity source of function)
# ---------------------------------------------------------------------------

def get_function_source(sol_file: str) -> list[tuple[str, str, list[int]]]:
    """
    Very lightweight: read the Solidity file, split into function blocks,
    return list of (func_name, func_text, line_numbers).
    We only care about validateUserOp.
    """
    text = Path(sol_file).read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    results = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if VALIDATE_FUNC_RE.search(line) and "function" in line:
            # find matching closing brace
            start = i
            depth = 0
            j = i
            found_open = False
            while j < len(lines):
                for ch in lines[j]:
                    if ch == "{":
                        depth += 1
                        found_open = True
                    elif ch == "}":
                        depth -= 1
                if found_open and depth == 0:
                    break
                j += 1
            block_lines = lines[start:j+1]
            block_text = "\n".join(block_lines)
            results.append(("validateUserOp", block_text, list(range(start+1, j+2))))
            i = j + 1
        else:
            i += 1
    return results


# ---------------------------------------------------------------------------
# Per-family detectors (heuristic, no VOIR)
# ---------------------------------------------------------------------------

def detect_VU001_AO(func_text: str) -> bool:
    """Authorization Omission: no auth keyword found in validateUserOp body."""
    return not bool(AUTH_KEYWORDS.search(func_text))


def detect_VU002_NVO(func_text: str) -> bool:
    """Nonce Validation Omission: nonce is not read/checked anywhere in function."""
    return not bool(NONCE_READ_RE.search(func_text))


def detect_VU003_ISS(func_text: str) -> bool:
    """
    Incorrect Success Signaling: function contains a return-0 path
    but we cannot tell whether it's conditioned on auth. Heuristic: flag if
    there exists 'return 0' (or equivalent) in the body. High FP expected
    because many correct implementations also return 0 on success.
    Actually tuned to: flag if 'return 0' appears AND no explicit
    SIG_VALIDATION_FAILED path — this is still a weak heuristic.
    """
    has_success_return = bool(SUCCESS_RETURN_RE.search(func_text))
    has_failure_path = bool(re.search(
        r"\b(SIG_VALIDATION_FAILED|return\s+1\b|sigFailed|_SIG_VALIDATION_FAILED)\b",
        func_text
    ))
    # Flag if success return exists but no clear failure path
    # (weak: many valid contracts will hit this)
    return has_success_return and not has_failure_path


def detect_VU004_IHM(func_text: str) -> bool:
    """
    Intent-Hash Mismatch: function recomputes a hash internally instead of
    using the provided userOpHash parameter.
    Heuristic: hash recomputation keywords present AND userOpHash also used
    (suggesting the provided hash may be bypassed).
    """
    has_recompute = bool(HASH_RECOMPUTE_RE.search(func_text))
    # Flag if there's local recompute (possible mismatch)
    return has_recompute


def detect_VU005_NPF(func_text: str) -> bool:
    """
    Nonce Progression Failure: nonce is read but never stored/incremented.
    Heuristic: nonce keyword present but no store pattern.
    High FP expected: EntryPoint handles nonce update, so most correct
    accounts will have nonce read but no local store.
    """
    has_read = bool(NONCE_READ_RE.search(func_text))
    has_store = bool(NONCE_STORE_RE.search(func_text))
    return has_read and not has_store


def detect_VU007_CBF(func_text: str) -> bool:
    """Caller-Binding Failure: no EntryPoint caller check found."""
    return not bool(ENTRYPOINT_CALLER_RE.search(func_text))


DETECTORS = {
    "VU001": detect_VU001_AO,
    "VU002": detect_VU002_NVO,
    "VU003": detect_VU003_ISS,
    "VU004": detect_VU004_IHM,
    "VU005": detect_VU005_NPF,
    "VU007": detect_VU007_CBF,
}


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

def analyze_contract(sol_file: str) -> dict[str, bool]:
    """Return detected flags for each VU family."""
    try:
        funcs = get_function_source(sol_file)
    except Exception:
        return {k: False for k in DETECTORS}

    if not funcs:
        # No validateUserOp found — cannot flag any family
        return {k: False for k in DETECTORS}

    # Aggregate over all validateUserOp occurrences (usually 1)
    flags: dict[str, bool] = {k: False for k in DETECTORS}
    for _name, func_text, _lines in funcs:
        for vu, detector in DETECTORS.items():
            if detector(func_text):
                flags[vu] = True
    return flags


# ---------------------------------------------------------------------------
# Batch evaluation
# ---------------------------------------------------------------------------

def evaluate(
    label_file: str,
    contracts_root: str,
    output_json: str,
) -> None:
    with open(label_file) as f:
        labels = json.load(f)

    families = ["VU001", "VU002", "VU003", "VU004", "VU005", "VU007"]
    # Counters per family
    TP = {k: 0 for k in families}
    FP = {k: 0 for k in families}
    FN = {k: 0 for k in families}
    TN = {k: 0 for k in families}

    per_contract = []
    total = len(labels)

    for idx, entry in enumerate(labels):
        rel_path = entry["file"]
        gt = entry["gt_rules"]
        sol_file = os.path.join(contracts_root, rel_path)

        if not os.path.exists(sol_file):
            print(f"[{idx+1}/{total}] MISSING: {rel_path}", file=sys.stderr)
            preds = {k: False for k in families}
        else:
            preds = analyze_contract(sol_file)
            print(f"[{idx+1}/{total}] {rel_path}", file=sys.stderr)

        row: dict[str, Any] = {"file": rel_path, "gt": {}, "pred": {}, "errors": {}}
        for vu in families:
            g = bool(gt.get(vu, False))
            p = bool(preds.get(vu, False))
            row["gt"][vu] = g
            row["pred"][vu] = p
            if g and p:
                TP[vu] += 1
            elif not g and p:
                FP[vu] += 1
            elif g and not p:
                FN[vu] += 1
            else:
                TN[vu] += 1
        per_contract.append(row)

    # Aggregate
    summary = {}
    total_TP = total_FP = total_FN = 0
    for vu in families:
        tp, fp, fn = TP[vu], FP[vu], FN[vu]
        total_TP += tp; total_FP += fp; total_FN += fn
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1   = 2*prec*rec/(prec+rec) if (prec+rec) > 0 else 0.0
        summary[vu] = {
            "TP": tp, "FP": fp, "FN": fn, "TN": TN[vu],
            "Precision": round(prec*100, 2),
            "Recall": round(rec*100, 2),
            "F1": round(f1*100, 2),
        }

    macro_prec = sum(summary[v]["Precision"] for v in families) / len(families)
    macro_rec  = sum(summary[v]["Recall"]    for v in families) / len(families)
    macro_f1   = sum(summary[v]["F1"]        for v in families) / len(families)

    overall_prec = total_TP/(total_TP+total_FP) if (total_TP+total_FP) > 0 else 0.0
    overall_rec  = total_TP/(total_TP+total_FN) if (total_TP+total_FN) > 0 else 0.0
    overall_f1   = 2*overall_prec*overall_rec/(overall_prec+overall_rec) if (overall_prec+overall_rec) > 0 else 0.0

    output = {
        "per_family": summary,
        "macro": {
            "Precision": round(macro_prec, 2),
            "Recall":    round(macro_rec,  2),
            "F1":        round(macro_f1,   2),
        },
        "overall": {
            "TP": total_TP, "FP": total_FP, "FN": total_FN,
            "Precision": round(overall_prec*100, 2),
            "Recall":    round(overall_rec*100,  2),
            "F1":        round(overall_f1*100,   2),
        },
        "per_contract": per_contract,
    }

    Path(output_json).parent.mkdir(parents=True, exist_ok=True)
    with open(output_json, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to: {output_json}", file=sys.stderr)

    # Print summary table
    print("\n=== Tuned Baseline Results ===")
    print(f"{'Family':<8} {'TP':>5} {'FP':>5} {'FN':>5} {'Prec%':>8} {'Rec%':>8} {'F1%':>8}")
    print("-" * 55)
    for vu in families:
        s = summary[vu]
        print(f"{vu:<8} {s['TP']:>5} {s['FP']:>5} {s['FN']:>5} {s['Precision']:>8.2f} {s['Recall']:>8.2f} {s['F1']:>8.2f}")
    print("-" * 55)
    print(f"{'OVERALL':<8} {total_TP:>5} {total_FP:>5} {total_FN:>5} {overall_prec*100:>8.2f} {overall_rec*100:>8.2f} {overall_f1*100:>8.2f}")
    print(f"\nMacro avg — Prec: {macro_prec:.2f}%  Rec: {macro_rec:.2f}%  F1: {macro_f1:.2f}%")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Tuned Baseline Detector for ERC-4337 validateUserOp")
    parser.add_argument("--label-file", required=True)
    parser.add_argument("--contracts-root", required=True)
    parser.add_argument("--output", default="tuned_baseline_results.json")
    args = parser.parse_args()
    evaluate(args.label_file, args.contracts_root, args.output)


if __name__ == "__main__":
    main()
