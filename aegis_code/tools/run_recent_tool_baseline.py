#!/usr/bin/env python3

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional


def load_json(path: Path):
    with path.open() as f:
        return json.load(f)


def longest_matching_root(file_path: str, roots: List[str]) -> Optional[str]:
    matches = [
        root for root in roots if file_path == root or file_path.startswith(root + "/")
    ]
    if not matches:
        return None
    return max(matches, key=len)


def parse_json_loose(text: str):
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    for start_char in ("[", "{"):
        start = text.find(start_char)
        if start != -1:
            candidate = text[start:]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue
    return None


def run_command(command: List[str], cwd: Optional[str], timeout: int):
    start = time.time()
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
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


def evaluate_solhint(
    file_path: str, cwd: Optional[str], timeout: int, config_path: Optional[str]
):
    if not config_path:
        raise ValueError("Solhint requires --solhint-config for this runner")
    result = run_command(
        ["solhint", "-c", config_path, "-f", "json", file_path], cwd, timeout
    )
    parsed = parse_json_loose(result["stdout"])
    findings = parsed if isinstance(parsed, list) else []
    problems = [f for f in findings if isinstance(f, dict) and f.get("ruleId")]
    return {
        **result,
        "flagged": len(problems) > 0,
        "finding_count": len(problems),
        "error_count": sum(1 for f in problems if f.get("severity") == "Error"),
        "warning_count": sum(1 for f in problems if f.get("severity") == "Warning"),
        "parse_ok": parsed is not None,
    }


def evaluate_soliditydefend(
    file_path: str, cwd: Optional[str], timeout: int, temp_dir: Path
):
    out_file = temp_dir / "soliditydefend_output.json"
    result = run_command(
        ["soliditydefend", "-f", "json", "-o", str(out_file), file_path],
        cwd,
        timeout,
    )
    parsed = load_json(out_file) if out_file.exists() else None
    findings = parsed.get("findings", []) if isinstance(parsed, dict) else []
    return {
        **result,
        "flagged": len(findings) > 0,
        "finding_count": len(findings),
        "parse_ok": parsed is not None,
        "statistics": parsed.get("statistics", {}) if isinstance(parsed, dict) else {},
        "metadata": parsed.get("metadata", {}) if isinstance(parsed, dict) else {},
    }


def evaluate_tameshi(
    file_path: str, cwd: Optional[str], timeout: int, tameshi_bin: str
):
    result = run_command(
        [tameshi_bin, "scan", "run", "-i", file_path, "--format", "json"],
        cwd,
        timeout,
    )
    parsed = parse_json_loose(result["stdout"])
    findings = parsed if isinstance(parsed, list) else []
    return {
        **result,
        "flagged": len(findings) > 0,
        "finding_count": len(findings),
        "parse_ok": parsed is not None,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--tool", required=True, choices=["solhint", "soliditydefend", "tameshi"]
    )
    parser.add_argument("--input-json", required=True)
    parser.add_argument("--roots-json", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--solhint-config")
    parser.add_argument("--tameshi-bin", default="/tmp/Tameshi/target/release/tameshi")
    args = parser.parse_args()

    eval_input = load_json(Path(args.input_json))
    root_rows = load_json(Path(args.roots_json))
    roots = [row["root"] for row in root_rows]
    files = eval_input["files"][: args.limit] if args.limit else eval_input["files"]

    output: Dict[str, dict] = {}
    for idx, file_path in enumerate(files, start=1):
        file_root = longest_matching_root(file_path, roots)
        cwd = file_root or str(Path(file_path).parent)

        if args.tool == "solhint":
            row = evaluate_solhint(file_path, cwd, args.timeout, args.solhint_config)
            row["config"] = args.solhint_config
        elif args.tool == "soliditydefend":
            row = evaluate_soliditydefend(file_path, cwd, args.timeout, Path(cwd))
        else:
            row = evaluate_tameshi(file_path, cwd, args.timeout, args.tameshi_bin)

        row["root"] = file_root
        output[file_path] = row
        print(
            f"[{idx}/{len(files)}] {args.tool}: flagged={row['flagged']} timeout={row['timeout']} parse_ok={row.get('parse_ok')} :: {file_path}",
            flush=True,
        )

    out_path = Path(args.output_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        json.dump(output, f, indent=2)
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
