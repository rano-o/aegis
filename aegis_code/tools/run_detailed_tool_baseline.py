#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional


SLITHER_BIN = "/Users/chenting/aa-sentry/.venv/bin/slither"
MYTH_BIN = "/Users/chenting/Library/Python/3.9/bin/myth"
SMARTCHECK_JAR = "/opt/homebrew/lib/node_modules/@smartdec/smartcheck/jdeploy-bundle/smartcheck-2.0-jar-with-dependencies.jar"
SMARTCHECK_JAVA_LIBS = [
    "/Users/chenting/aa-sentry/.tooling/java-libs/jaxb-api-2.3.1.jar",
    "/Users/chenting/aa-sentry/.tooling/java-libs/jaxb-core-2.3.0.1.jar",
    "/Users/chenting/aa-sentry/.tooling/java-libs/jaxb-impl-2.3.3.jar",
    "/Users/chenting/aa-sentry/.tooling/java-libs/activation-1.1.1.jar",
]


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def longest_matching_root(file_path: str, roots: List[str]) -> Optional[str]:
    matches = [
        root for root in roots if file_path == root or file_path.startswith(root + "/")
    ]
    return max(matches, key=len) if matches else None


def parse_json_loose(text: str):
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for start_char in ("[", "{"):
        idx = text.find(start_char)
        if idx >= 0:
            try:
                return json.loads(text[idx:])
            except json.JSONDecodeError:
                continue
    return None


def run_command(
    command: List[str],
    cwd: Optional[str],
    timeout: int,
    env: Optional[Dict[str, str]] = None,
):
    start = time.time()
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=merged_env,
        )
        return {
            "timeout": False,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "elapsed_sec": round(time.time() - start, 4),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "timeout": True,
            "exit_code": None,
            "stdout": exc.stdout.decode()
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or ""),
            "stderr": exc.stderr.decode()
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or ""),
            "elapsed_sec": round(time.time() - start, 4),
        }


def normalize_findings(findings: List[dict]) -> List[dict]:
    out = []
    for f in findings:
        line = f.get("line")
        if isinstance(line, int):
            out.append(f)
    return out


def eval_slither(file_path: str, cwd: str, timeout: int):
    result = run_command(
        [SLITHER_BIN, file_path, "--json", "-", "--json-types", "detectors"],
        cwd,
        timeout,
    )
    payload = parse_json_loose(result["stdout"]) or {}
    detectors = (
        payload.get("results", {}).get("detectors", [])
        if isinstance(payload, dict)
        else []
    )
    findings = []
    for d in detectors:
        line = None
        for e in d.get("elements", []):
            sm = e.get("source_mapping", {})
            lines = sm.get("lines", [])
            if lines:
                line = min(lines)
                break
        findings.append(
            {
                "line": line,
                "rule_id": d.get("check", ""),
                "message": d.get("description", ""),
                "severity": d.get("impact", ""),
            }
        )
    findings = normalize_findings(findings)
    return {
        **result,
        "parse_ok": isinstance(payload, dict),
        "flagged": len(findings) > 0,
        "finding_count": len(findings),
        "findings": findings,
    }


def eval_aderyn(file_path: str, root: str, timeout: int):
    rel = os.path.relpath(file_path, root)
    with tempfile.NamedTemporaryFile(
        prefix="aderyn_", suffix=".json", delete=False
    ) as tf:
        out_file = tf.name
    result = run_command(["aderyn", root, "-i", rel, "-o", out_file], root, timeout)
    payload = {}
    if Path(out_file).exists() and Path(out_file).stat().st_size > 0:
        try:
            payload = load_json(Path(out_file))
        except json.JSONDecodeError:
            payload = {}
    findings = []
    for bucket, sev in (("high_issues", "high"), ("low_issues", "low")):
        issues = (
            payload.get(bucket, {}).get("issues", [])
            if isinstance(payload, dict)
            else []
        )
        for issue in issues:
            rid = issue.get("detector_name", "")
            msg = issue.get("description", "") or issue.get("title", "")
            for inst in issue.get("instances", []):
                cpath = inst.get("contract_path", "")
                line = inst.get("line_no")
                if isinstance(line, int) and (cpath == rel or cpath.endswith(rel)):
                    findings.append(
                        {"line": line, "rule_id": rid, "message": msg, "severity": sev}
                    )
    findings = normalize_findings(findings)
    return {
        **result,
        "parse_ok": isinstance(payload, dict),
        "flagged": len(findings) > 0,
        "finding_count": len(findings),
        "findings": findings,
    }


def eval_mythril(file_path: str, root: str, timeout: int):
    rel = os.path.relpath(file_path, root)
    contract = Path(file_path).stem
    target = f"{rel}:{contract}"
    solc_args = f"--allow-paths {root} --base-path {root} --include-path {root}/lib"
    result = run_command(
        [
            MYTH_BIN,
            "analyze",
            target,
            "--execution-timeout",
            str(max(8, min(timeout, 20))),
            "--solver-timeout",
            "5000",
            "--max-depth",
            "32",
            "--outform",
            "jsonv2",
            "--solc-args",
            solc_args,
        ],
        root,
        timeout,
    )
    payload = parse_json_loose(result["stdout"]) or []
    issues = []
    if isinstance(payload, list) and payload:
        issues = payload[0].get("issues", []) or []
    findings = []
    for issue in issues:
        line = None
        loc = issue.get("sourceLocation", {})
        if isinstance(loc, dict):
            line = loc.get("line")
        findings.append(
            {
                "line": line,
                "rule_id": issue.get("check", "") or issue.get("title", ""),
                "message": issue.get("description", "") or issue.get("title", ""),
                "severity": issue.get("severity", ""),
            }
        )
    findings = normalize_findings(findings)
    return {
        **result,
        "parse_ok": isinstance(payload, list),
        "flagged": len(findings) > 0,
        "finding_count": len(findings),
        "findings": findings,
    }


def eval_smartcheck(file_path: str, cwd: str, timeout: int):
    cp = ":".join([SMARTCHECK_JAR] + SMARTCHECK_JAVA_LIBS)
    env = {
        "JAVA_HOME": "/opt/homebrew/opt/openjdk",
        "PATH": f"/opt/homebrew/opt/openjdk/bin:{os.environ.get('PATH', '')}",
    }
    result = run_command(
        ["java", "-cp", cp, "ru.smartdec.smartcheck.app.cli.Tool", "-p", file_path],
        cwd,
        timeout,
        env=env,
    )
    findings = []
    current = {}
    for line in (result["stdout"] or "").splitlines():
        s = line.strip()
        if s.startswith("ruleId:"):
            current["rule_id"] = s.split(":", 1)[1].strip()
        elif s.startswith("line:"):
            try:
                current["line"] = int(s.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif s.startswith("severity:"):
            current["severity"] = s.split(":", 1)[1].strip()
        elif s.startswith("content:"):
            current["message"] = s.split(":", 1)[1].strip()
        elif s == "" and current:
            findings.append(current)
            current = {}
    if current:
        findings.append(current)
    findings = normalize_findings(findings)
    return {
        **result,
        "parse_ok": True,
        "flagged": len(findings) > 0,
        "finding_count": len(findings),
        "findings": findings,
    }


def eval_soliditydefend(file_path: str, cwd: str, timeout: int):
    with tempfile.NamedTemporaryFile(
        prefix="soliditydefend_", suffix=".json", delete=False
    ) as tf:
        out_file = tf.name
    result = run_command(
        ["soliditydefend", "-f", "json", "-o", out_file, file_path], cwd, timeout
    )
    payload = load_json(Path(out_file)) if Path(out_file).exists() else {}
    findings = []
    for f in payload.get("findings", []):
        loc = f.get("location", {})
        findings.append(
            {
                "line": loc.get("line"),
                "rule_id": f.get("detector_id", ""),
                "message": f.get("message", ""),
                "severity": f.get("severity", ""),
            }
        )
    findings = normalize_findings(findings)
    return {
        **result,
        "parse_ok": isinstance(payload, dict),
        "flagged": len(findings) > 0,
        "finding_count": len(findings),
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--tool",
        required=True,
        choices=["slither", "aderyn", "mythril", "smartcheck", "soliditydefend"],
    )
    parser.add_argument("--input-json", required=True)
    parser.add_argument("--roots-json", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--start-index", type=int, default=1)
    parser.add_argument("--end-index", type=int, default=0)
    args = parser.parse_args()

    eval_input = load_json(Path(args.input_json))
    roots_json = load_json(Path(args.roots_json))
    roots = [r["root"] for r in roots_json]
    files_all = eval_input["files"][: args.limit] if args.limit else eval_input["files"]
    start = max(1, args.start_index)
    end = args.end_index if args.end_index > 0 else len(files_all)
    files = files_all[start - 1 : end]

    out_path = Path(args.output_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out: Dict[str, dict] = {}
    if out_path.exists() and out_path.stat().st_size > 0:
        try:
            loaded = load_json(out_path)
            if isinstance(loaded, dict):
                out = loaded
        except json.JSONDecodeError:
            out = {}

    for idx, file_path in enumerate(files, start=start):
        root = longest_matching_root(file_path, roots)
        cwd = root or str(Path(file_path).parent)
        if args.tool == "slither":
            row = eval_slither(file_path, cwd, args.timeout)
        elif args.tool == "aderyn":
            row = eval_aderyn(file_path, cwd, args.timeout)
        elif args.tool == "mythril":
            row = eval_mythril(file_path, cwd, args.timeout)
        elif args.tool == "smartcheck":
            row = eval_smartcheck(file_path, cwd, args.timeout)
        else:
            row = eval_soliditydefend(file_path, cwd, args.timeout)

        row["root"] = root
        out[file_path] = row
        out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(
            f"[{idx}/{len(files_all)}] {args.tool}: findings={row['finding_count']} timeout={row['timeout']} parse_ok={row.get('parse_ok')} :: {file_path}",
            flush=True,
        )

    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
