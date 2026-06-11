# aifuzz — AI-Assisted Fuzzing for Smart Contract Security

**Singapore Institute of Technology (SIT) — IWL2** · Supervisor: Prof Purnima Mohan

Give `aifuzz` a Solidity contract; it deploys the contract to a local
blockchain, **fuzzes transaction sequences** to drive it into vulnerable states,
and reports the vulnerabilities it finds. Its distinguishing feature is
**AI-guided input generation** — a local LLM proposes properties and transaction
sequences to reach bugs that plain **random** fuzzing misses.

```bash
aifuzz analyze dataset/vulnerable/reentrancy/simple_dao.sol --mode ai-guided
```

---

## How it works (end to end)

```
aifuzz analyze <contract.sol>
  1. compile the Solidity
  2. AI step (aifuzz/ai_guidance.py): a LOCAL model (Llama 3 via Ollama) reads the
     contract + retrieves vuln patterns from ChromaDB, and drafts
       • properties — rules that must always hold
       • seed transaction sequences likely to break them
  3. deploy to a local chain (Anvil)            ← the "testing environment"
  4. fuzz (aifuzz/fuzzer.py = Echidna): fire many tx-sequences trying to
     break the properties — in two modes: RANDOM vs AI-GUIDED
  5. report (aifuzz/report.py): violations → JSON / Markdown / SARIF → dashboard
```

The project's headline result is the **random vs AI-guided** comparison:
AI guidance should reach states and find bugs that random fuzzing does not.

---

## Layout

```
aifuzz/        the tool — cli, analyzer, fuzzer (Echidna), ai_guidance (Ollama+ChromaDB),
               local_chain (Anvil), report (findings → JSON/Markdown/SARIF), config
dashboard/     Flask web UI to submit a contract and view its report
dataset/       the testing environment + evaluation set: labelled .sol contracts
               (vulnerable/ + clean/), labels.csv, generate_labels.py, provenance
tests/         a small pytest suite for the report layer
benchmark.py   evaluation: runs the tool over dataset/ → random-vs-AI + P/R/F1
.claude/agents/ Claude Code helper agents used while developing (see below)
```

## Deliverable map (IWL2)

| # | Deliverable | Where |
|---|-------------|-------|
| 1 | AI-assisted fuzzing framework | `aifuzz/` (esp. `fuzzer.py` + `ai_guidance.py`) |
| 2 | Smart contract testing environment | `aifuzz/local_chain.py` (local Anvil) + `dataset/` |
| 3 | Vulnerability analysis report + PoC exploits | `benchmark.py` → `results/` metrics; PoCs authored via the `exploit-writer` agent |
| 4 | Web dashboard | `dashboard/` |
| 5 | User guide + final presentation | this README (guide); presentation deck separate |

---

## Quick start

**Docker (recommended)** — bundles the Linux toolchain (Echidna, Anvil, solc)
and the local AI, so nothing fragile installs on your host:

```bash
cp .env.example .env
docker compose up          # dashboard → http://localhost:5000
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
# → starts a local Anvil chain, deploys the contract, prints its address + owner()
```

**Evaluate over the dataset:**

```bash
python dataset/generate_labels.py    # refresh labels.csv (ground truth)
python benchmark.py                  # random-vs-AI + Precision/Recall/F1
```

**Run the tests:** `pytest`

---

## Vulnerability focus

Reentrancy, access-control flaws, and logic/state inconsistencies — exercised by
stateful, multi-step transaction fuzzing. The `dataset/` also includes
oracle-manipulation and ordering-attack contracts for broader coverage.

## Dataset provenance

Contracts in `dataset/` come from public academic repos (SmartBugs, SWC,
Not-So-Smart-Contracts, Damn Vulnerable DeFi). Full citations + licences:
[dataset/DATASET_PROVENANCE.md](dataset/DATASET_PROVENANCE.md).

## Status

Working today: **random fuzzing** (`aifuzz analyze` finds real bugs via Echidna)
and the **local blockchain** (`aifuzz deploy` — Anvil deploy + transact + query).
The findings/report layer, CLI, dashboard, and evaluation math are in place.
Remaining milestones: **M3** AI-guided fuzzing (the novelty), **M4** dashboard
wiring, **M5** full evaluation + PoC exploits. Until an engine lands, commands
report what's pending rather than fabricating results.

Tested on: Windows 11 (Docker Desktop), macOS 14 (Docker Desktop).
