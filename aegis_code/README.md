# aa-sentry (Phase 1)

Static analyzer for **ERC-4337-specific** issues using **Slither + custom passes**.

## Covered classes (phase 1)

1. `validateUserOp` authorization/replay logic issues
2. `UserOperation` hash/pack consistency issues
3. `Paymaster` validation/accounting issues

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install slither-analyzer
```

## Run

```bash
.venv/bin/python src/aa4337_analyzer.py tests/VulnerableAA.sol \
  --solc /Users/$USER/.solc-select/artifacts/solc-0.8.20/solc-0.8.20 \
  --json-out findings.json
```

For real-world projects with dependency imports, pass remappings/include paths:

```bash
.venv/bin/python src/aa4337_analyzer.py \
  datasets/real_small/sources/account-abstraction/contracts/accounts/SimpleAccount.sol \
  --solc /Users/$USER/.solc-select/artifacts/solc-0.8.28/solc-0.8.28 \
  --solc-remaps "@openzeppelin/=datasets/real_small/vendor/@openzeppelin/" \
  --solc-args "--base-path $(pwd) --include-path $(pwd)/datasets/real_small/vendor --include-path $(pwd)/datasets/real_small/sources/account-abstraction"
```

## Small real-contract dataset validation (<=100)

Build dataset manifest (sampled from real `eth-infinitism/account-abstraction` contracts):

```bash
.venv/bin/python tools/build_small_dataset.py
```

Run batch evaluation and produce summary reports:

```bash
.venv/bin/python tools/run_dataset_eval.py \
  --solc /Users/$USER/.solc-select/artifacts/solc-0.8.28/solc-0.8.28
```

Outputs:

- `datasets/real_small/manifest.json`
- `datasets/real_small/results/summary.json`
- `datasets/real_small/results/details.json`

## Large real-contract ERC-4337 dataset

Build a large-scale dataset from multiple real repositories (core AA + ecosystem projects):

```bash
.venv/bin/python tools/build_large_4337_dataset.py \
  --out-dir datasets/aa4337_large \
  --max-files 3000
```

Main output:

- `datasets/aa4337_large/manifest.json`
- `datasets/aa4337_large/contracts/**` (deduplicated Solidity files)
- `datasets/aa4337_large/sources/**` (cloned source repos)

Run analyzer over the large dataset:

```bash
.venv/bin/python tools/eval_large_dataset.py \
  --dataset-dir datasets/aa4337_large \
  --solc /Users/$USER/.solc-select/artifacts/solc-0.8.28/solc-0.8.28
```

Evaluation outputs:

- `datasets/aa4337_large/results/summary.json`
- `datasets/aa4337_large/results/details.json`

## Output

- Console summary by rule
- Detailed findings with source location
- Optional JSON report (`--json-out`)

## Notes

- This is a **high-recall phase-1 detector** and may produce false positives.
- Intended pipeline: static findings -> LLM semantic triage (phase 2).
