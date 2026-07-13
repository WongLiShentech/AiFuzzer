# aifuzz — AI-Assisted Fuzzing for Smart Contract Security

**Singapore Institute of Technology (SIT) — IWL2** · Supervisor: Prof Purnima Mohan

Give `aifuzz` a Solidity contract; it reads the contract, builds a fuzzing
harness for it, **fuzzes transaction sequences** to drive it into vulnerable
states, and reports the vulnerabilities it finds. Its distinguishing feature is
**AI-guided harness + input generation** — a local LLM proposes harnesses,
properties, and transaction sequences to reach bugs that plain **random** fuzzing
misses.

```bash
aifuzz analyze tests/fixtures/vulnerable/reentrancy/simple_dao.sol --mode ai-guided
```

---

## How it works (end to end)

```
aifuzz analyze <contract.sol>
  1. understand it (aifuzz/synthesize.py): Slither parses the contract (regex
     fallback) and detects which vulnerability shapes it matches
  2. build a harness per matched shape — an attacker + an echidna_* invariant:
       random mode (M2, working):  generated from a template
       AI mode    (M3, the novelty): a local LLM (Ollama) + RAG over the dataset
                  (ChromaDB) generates the harness + smarter seed inputs
  3. fuzz (aifuzz/fuzzer.py = Echidna): drive many transaction sequences trying to
     break the invariant, in Echidna's OWN EVM — recording code coverage + time
  4. report (aifuzz/report.py): findings + coverage -> JSON / Markdown / SARIF -> dashboard
```

The project's headline result is the **random vs AI-guided** comparison: AI
guidance should reach states and find bugs that random fuzzing does not. (The fuzz
loop runs in Echidna's internal EVM; the Anvil local chain is used only for
deploy / proof-of-concept exploits — see `aifuzz deploy` below.)

---

## Layout

```
aifuzz/            the tool (Python package). One responsibility per module:
                     cli.py          command-line entry point (analyze / deploy / suite)
                     analyzer.py     orchestrates a full analysis of one contract
                     synthesize.py   auto-builds an Echidna harness per detected vuln shape
                     fuzzer.py       runs Echidna; parses findings + code coverage
                     ai_guidance.py  M3 RAG: local LLM (Ollama) + ChromaDB retrieval
                     local_chain.py  local Anvil chain for deploy / PoC exploits
                     report.py       findings -> JSON / Markdown / SARIF
                     suite.py        runs the labelled evaluation suite
                     config.py       all settings, env-driven (nothing hardcoded)
dashboard/         Flask web UI: upload a contract, view its report
harnesses/         hand-written Echidna harnesses (+ .yaml configs) for the eval suite,
                   one per in-scope vuln type; registry.yaml maps target -> harness -> expect
examples/          small demo contracts (safe + vulnerable) for trying the tool / dashboard
tests/             pytest suite + fixtures/ (small offline labelled sample: vulnerable/,
                   clean/, labels.csv, provenance) used by CI, `aifuzz suite`, and demos
docs/              design notes: LIMITATIONS, code-coverage, metrics-proposal, semantics-parsing
benchmark.py       evaluation harness: runs the tool over the labelled set -> random-vs-AI + P/R/F1
Dockerfile         Linux image bundling the toolchain (Echidna, Anvil, solc) + the AI extras
docker-compose.yml one-command stack: the aifuzz app + a local Ollama sidecar
reference-paper.pdf the IEEE reference paper (evaluation methodology, not the target)
.claude/agents/    Claude Code helper agents used while developing (see below)
```

The full labelled benchmark corpus lives on Hugging Face (see **Dataset** below), **not**
in this repo — only the small `tests/fixtures/` sample is kept here for offline CI/demos.

## Deliverable map (IWL2)

| # | Deliverable | Where |
|---|-------------|-------|
| 1 | AI-assisted fuzzing framework | `aifuzz/` (esp. `synthesize.py` + `fuzzer.py` + `ai_guidance.py`) |
| 2 | Smart contract testing environment | `aifuzz/local_chain.py` (local Anvil) + `tests/fixtures/` (sample) + HF dataset |
| 3 | Vulnerability analysis report + PoC exploits | `benchmark.py` -> `results/` metrics; PoCs authored via the `exploit-writer` agent |
| 4 | Web dashboard | `dashboard/` |
| 5 | User guide + final presentation | this README (guide); presentation deck separate |

---

## Dataset

The full labelled benchmark corpus (~10k contracts, in progress) is hosted on **Hugging
Face**: [`Ai-Fuzz/smart-contracts`](https://huggingface.co/datasets/Ai-Fuzz/smart-contracts).
`tests/fixtures/` holds only a small offline sample used by the tests, the `aifuzz suite`,
and demos; the full corpus is fetched from Hugging Face for the random-vs-AI evaluation.

---

## Quick start

**Docker (recommended)** — bundles the Linux toolchain (Echidna, Anvil, solc)
and the local AI, so nothing fragile installs on your host:

```bash
cp .env.example .env
docker compose up          # dashboard -> http://localhost:5000
```

**Local CLI:**

```bash
pip install -e .
python -m aifuzz.cli analyze harnesses/AccessControlHarness.sol --contract-name AccessControlEchidnaTest
python -m aifuzz.cli analyze <contract>.sol --mode ai-guided --format sarif
```

**Local blockchain (deploy a contract to Anvil and query it):**

```bash
python -m aifuzz.cli deploy harnesses/AccessControlHarness.sol \
    --contract-name AccessControlEchidnaTest --call owner
# -> starts a local Anvil chain, deploys the contract, prints its address + owner()
```

**Evaluate over the dataset:**

```bash
python tests/fixtures/generate_labels.py   # refresh the sample's labels.csv (ground truth)
python benchmark.py                        # random-vs-AI + Precision/Recall/F1 + coverage
```

**Run the tests:** `pytest`

---

## Vulnerability focus

Four EEA EthTrust v3 types, exercised by stateful, multi-step transaction
fuzzing: **reentrancy, access control, ordering attacks (transaction-order
dependence), and oracle manipulation**.

## Dataset provenance

The small offline sample in `tests/fixtures/` comes from public academic repos
(SmartBugs, SWC, Not-So-Smart-Contracts, Damn Vulnerable DeFi); citations +
licences: [tests/fixtures/DATASET_PROVENANCE.md](tests/fixtures/DATASET_PROVENANCE.md).
The full benchmark corpus is hosted on Hugging Face (see **Dataset** above).

## Status

Working today: **random fuzzing with automatic harness synthesis** — `aifuzz
analyze <contract> --auto` reads a raw contract, detects its shape via Slither
(regex fallback), generates a harness **per matched type**, and fuzzes it via
Echidna, reporting findings + **code coverage**. Also working: the **local
blockchain** (`aifuzz deploy` — Anvil deploy/transact/query), the report layer
(JSON/Markdown/SARIF), CLI, **dashboard**, and `benchmark.py` (P/R/F1/FPR +
coverage + time + a composite score). Remaining: **M3** AI-guided harness + input
generation (the novelty) and the **M5** AI column of the evaluation + PoC
exploits. Honest scaffolding: until an engine lands, commands report what's
pending rather than fabricating results.

Tested on: Windows 11 (Docker Desktop), macOS 14 (Docker Desktop).
