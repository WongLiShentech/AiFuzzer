# Code coverage for random fuzzing

## What it is

Code coverage is **how much of the contract's code the fuzzer actually executed**
during a run. A fuzzer can only find a bug in code it runs, so coverage measures
how *thorough* the fuzzing was: high coverage means most of the contract was
exercised; low coverage means large parts were never reached, and a bug there
would be missed.

(Mental model: the contract is a building of rooms — functions and branches. The
fuzzer is a robot trying doors. Coverage is the fraction of rooms it actually
entered.)

## Where the number comes from

We do not compute it by hand — Echidna is **coverage-guided** and reports it:

- Every line compiles to EVM instructions, each at a numbered location.
- As Echidna fires each transaction, the EVM records which locations execute.
- It keeps a running set of **distinct locations reached** across the whole
  campaign. The size of that set is the `cov:` value on Echidna's status lines
  (e.g. `cov: 609`).

So `cov: 609` means the fuzzer executed 609 distinct code points in the contract.
Running with `--corpus-dir` also writes an annotated `covered.*.txt` — the source
with a gutter marker per line (`*` executed, `r` reverted, blank = never reached).

## How it is wired into the tool

- `aifuzz/fuzzer.py` parses the final `cov:` value and times the run.
- `aifuzz/report.py` carries `coverage` and `elapsed`; they appear in the
  Markdown/JSON report and on the dashboard result panel.
- `benchmark.py` aggregates coverage (and time) per mode, mean ± stdev.

## How to show it

- **In the tool:** `aifuzz analyze <contract> --auto` — the report now prints
  `Coverage: N code points reached` and `Time: Ns`; the dashboard shows the same.
- **The annotated report (visual proof):**
  ```
  echidna harnesses/OracleManipulationHarness.sol --contract OracleManipEchidnaTest \
    --test-limit 50000 --corpus-dir /tmp/cov && cat /tmp/cov/covered.*.txt
  ```
  Open the printed source and point at the `*`/`r` markers — that is the fuzzer's
  reach, line by line.

## Why it matters for the project

Coverage is the headline metric for the random-vs-AI comparison: same contract,
same transaction budget, run under each mode — AI-guided input generation should
reach a **higher** `cov:` (or hit branches random never does, e.g. behind a
magic-value guard). That increase is the evidence that guidance beats random.
