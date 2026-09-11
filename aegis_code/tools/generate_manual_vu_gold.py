#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


RULES = ["VU001", "VU002", "VU003", "VU004", "VU005", "VU007"]


def _norm(text: str) -> str:
    return " ".join(text.split()).lower()


def _labels(**overrides: bool) -> dict[str, bool]:
    base = {rule: False for rule in RULES}
    base.update(overrides)
    return base


def _manual_label_for_snippet(snippet: str) -> tuple[dict[str, bool], str]:
    s = _norm(snippet)

    if "delegatetomanager()" in s:
        return _labels(), "manual cluster: fallback delegates validateUserOp to manager; no direct VU finding on wrapper"

    if "_requirefromentrypoint(); validationdata = _validatesignature(userop, userophash);" in s:
        return _labels(), "manual cluster: BaseAccount-style delegation with caller gate, signature helper, nonce helper"

    if "threshold == 1" in s and "hash.recover(userop.signature)" in s and "nonce = bytes32(uint256(nonce) + 1)" in s:
        return _labels(), "manual cluster: Gnosis manager validates caller/signature/hash and updates nonce"

    if "owner != hash.recover(userop.signature)" in s and "_validateandupdatenonce(userop)" in s:
        return _labels(VU004=True), "manual cluster: account authenticates but ignores provided userOpHash parameter and recomputes hash"

    if "require(msgsender == entrypoint" in s and "hash = userophash.toethsignedmessagehash()" in s and "nonce = bytes32(uint256(nonce) + 1)" in s:
        return _labels(), "manual cluster: manager authenticates with provided userOpHash, enforces caller gate, and updates nonce"

    if "touchstorage" in s or "touchpaymaster" in s:
        return _labels(VU001=True, VU003=True, VU005=True, VU007=True), "manual cluster: warm/cold side-channel account reads nonce but lacks auth/caller gate and returns raw success"

    if "basefe we pass off-chain as nonce" in s:
        return _labels(VU001=True, VU003=True, VU005=True, VU007=True), "manual cluster: malformed nonce-based pseudo-check without auth/caller gate"

    if "basefe we pass off-chain in the signature" in s:
        return _labels(VU001=True, VU002=True, VU003=True, VU007=True), "manual cluster: malicious account uses signature bytes as opaque data, no auth/no nonce/no caller gate"

    if "return sig_validation_success;" in s and "ep.depositto" in s:
        return _labels(VU001=True, VU002=True, VU003=True, VU007=True), "manual cluster: revert-test account returns constant success without auth/nonce/caller gate"

    if "return 0;" in s and "ep.depositto" in s:
        return _labels(VU001=True, VU002=True, VU003=True, VU007=True), "manual cluster: revert-test account returns raw success without auth/nonce/caller gate"

    raise ValueError(f"Unclassified validateUserOp snippet: {snippet[:160]}")


def _extract_validate_userop_body(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="ignore")
    pattern = re.compile(
        r"function\s+validateUserOp\s*\((.*?)\)\s*([^{};]*?)\{",
        re.IGNORECASE | re.DOTALL,
    )
    match = pattern.search(text)
    if not match:
        raise ValueError(f"validateUserOp body not found in {path}")
    start = match.start()
    brace = match.end() - 1
    depth = 0
    end = brace
    while end < len(text):
        ch = text[end]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end += 1
                break
        end += 1
    return text[start:end]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate manual gold labels for enriched validateUserOp implementations")
    parser.add_argument("--candidates", default="/Users/chenting/aa-sentry/datasets/aa4337_real_vuln_enriched/results/manual_review_candidates.json")
    parser.add_argument("--out", default="/Users/chenting/aa-sentry/datasets/aa4337_real_vuln_enriched/results/manual_gold_labels_vu001_vu007.json")
    args = parser.parse_args()

    candidates = json.loads(Path(args.candidates).read_text(encoding="utf-8"))
    out = []
    for idx, rec in enumerate(candidates):
        body = _extract_validate_userop_body(Path(rec["file"]))
        gt_rules, rationale = _manual_label_for_snippet(body)
        out.append(
            {
                "file": rec["file"],
                "contract": rec.get("contract", ""),
                "function": rec.get("function", "validateUserOp"),
                "function_index": idx,
                "gt_rules": gt_rules,
                "rationale": rationale,
                "snippet": rec["snippet"],
                "body": body,
            }
        )
    Path(args.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps({"count": len(out), "out": args.out}, indent=2))


if __name__ == "__main__":
    main()
