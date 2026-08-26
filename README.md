# aifuzz — AI-Assisted Fuzzing for Smart Contract Security

**Singapore Institute of Technology (SIT) — IWL2** · Supervisor: Prof. Purnima Mohan

Give `aifuzz` a Solidity contract. It parses the contract, **automatically builds an Echidna
fuzzing harness** for it, drives thousands of transaction sequences against a local EVM to break
the contract's security invariants, and reports each vulnerability with the exact transaction
sequence that triggers it.

The research question is a controlled one: **can a local LLM choose smarter fuzzing inputs than
random search?** The tool answers it by running the *same* harness two ways — once with Echidna's
random sampler, once seeded by a retrieval-augmented model — so any difference is attributable to
input generation alone.

---

## What it does

```
 contract.sol
     │
     ├─ 1. PARSE      Slither builds a structural model (functions, params, ether flow)
     ├─ 2. HARNESS    a deterministic template forwards the whole public ABI + attaches an
     │                oracle (echidna_* invariant) for each vulnerability shape detected
     ├─ 3. FUZZ       Echidna drives 50k transaction sequences in its own EVM, checking every
     │                invariant after each one
     └─ 4. REPORT     verdict + coverage + the falsifying call sequence  →  JSON / Markdown / SARIF / dashboard
```

**The four experimental arms.** The dashboard exposes the first two; all four are runnable from
`benchmark_testset.py` and are what the evaluation compares.

| Arm | Harness | Inputs | Purpose |
|---|---|---|---|
| **A — Random** | template | Echidna's random sampler | baseline |
| **B1 — AI-guided inputs** | *same template, byte-identical to A* | LLM (RAG) proposes the transaction sequences | the research question: isolates input generation |
| **B2 — AI-authored harness** | LLM writes the harness | random sampler | ablation: tests unaided harness synthesis |
| **B3 — Full AI pipeline** | LLM writes the harness | LLM proposes the inputs | both stages combined |

Detects four EEA EthTrust v3 vulnerability classes via stateful, multi-step fuzzing:
**reentrancy, access control, ordering attacks (transaction-order dependence), and oracle
manipulation.**

---

## Read this first: what cloning does and does not give you

Cloning this repo gives you the **code only**. It does **not** include the reference dataset or the
vector database — those are intentionally kept out of git (the dataset is large and versioned
separately; the vector store is derived data, hundreds of MB, and regenerable).

**Consequence:** out of the box you can run **random fuzzing** at full strength immediately. But the
**AI modes rely on retrieval** from a reference set of ~5k contracts, and a fresh clone has **none of
them** — so the AI runs with an *empty* knowledge base and performs far below its real ability. To
get the tool's full power you must **download the dataset from Hugging Face and embed it into the
vector database yourself** (Step 3 below). This is a one-time setup.

Three separate things, kept separate on purpose:

| Layer | Where it lives | In this repo? |
|---|---|---|
| **Code** | this git repo | included |
| **Reference dataset** (~5k contracts) | Hugging Face: [`Ai-Fuzz/smart-contracts`](https://huggingface.co/datasets/Ai-Fuzz/smart-contracts) | download separately |
| **Vector database** (embeddings) | local `chroma_data/` | built by you, on first run |

---

## Setup

### Prerequisites
- **[Docker Desktop](https://www.docker.com/products/docker-desktop/)** — bundles the whole Linux
  toolchain (Echidna, solc, crytic-compile) and the local Ollama LLM, so nothing fragile installs on
  your host. This is the only hard requirement.
- ~6 GB free disk for the two AI models; ~6 GB VRAM makes AI modes fast (they also run on CPU,
  slower).

### Step 1 — start the stack
```bash
git clone <this-repo> && cd AI-Fuzzing-Framework
cp .env.example .env
docker compose up -d          # dashboard → http://localhost:5000
```
Open **http://localhost:5000**. **Random fuzzing works now** — no models, no dataset needed. Try it
on the contracts in [`examples/`](examples/).

### Step 2 — pull the AI models (needed for the AI modes)
```bash
docker compose exec ollama ollama pull qwen2.5-coder:7b   # generator  (~4.7 GB)
docker compose exec ollama ollama pull nomic-embed-text   # embedder   (~0.3 GB)
```
The **generator** writes harnesses / proposes inputs; the **embedder** turns contracts into vectors
for retrieval. Both are local — nothing leaves your machine. (Swap either via `OLLAMA_MODEL` /
`EMBED_MODEL` in `.env`.)

### Step 3 — get the reference dataset and embed it (unlocks the AI's full power)
Without this, the AI has nothing to retrieve. To match the results in the paper:

```bash
# a) download the reference contracts from Hugging Face into ./dataset/
#    (git-lfs, the huggingface-cli, or a plain download of the repo all work)
git lfs install
git clone https://huggingface.co/datasets/Ai-Fuzz/smart-contracts dataset

#    .env already points RAG_CORPUS_DIR=dataset — no edit needed.

# b) build the vector database from it. The index builds itself the FIRST time any AI mode
#    runs, so just trigger one analysis and it embeds every .sol under ./dataset/ once,
#    then persists in chroma_data/ (and the chroma-data Docker volume) for all future runs:
docker compose exec aifuzz python -m aifuzz.cli analyze examples/reentrancy_withdraw_all.sol \
    --auto --mode ai-seed
```
First run is slow (it embeds the whole corpus); every run after is fast. Check how many contracts
got embedded:
```bash
docker compose exec aifuzz python -c "import chromadb; print(chromadb.PersistentClient(path='chroma_data').get_or_create_collection('aifuzz-knowledge').count())"
```

> The dataset is split into a **reference** set (embedded for retrieval) and a **held-out test** set;
> the tool never retrieves a test contract. See the dataset card on Hugging Face for the split and
> provenance.

---

## Using it

### Dashboard
Upload or paste a contract, choose **Random** or **AI-guided inputs**, and read the verdict.
Both modes are also available when scanning a Git repository. A vulnerable result shows the vulnerability class, the falsifying transaction
sequence (proof of exploit), and the generated attacker+oracle harness Echidna actually ran.

### CLI
```bash
pip install -e .

# analyze one raw contract (auto-synthesises a harness from its shape)
python -m aifuzz.cli analyze examples/reentrancy_withdraw_all.sol --auto --mode random
python -m aifuzz.cli analyze examples/reentrancy_withdraw_all.sol --auto --mode ai-seed   # AI inputs
python -m aifuzz.cli analyze examples/reentrancy_withdraw_all.sol --auto --mode ai-seed-cot  # AI inputs, planned
python -m aifuzz.cli analyze <contract>.sol --auto --mode ai-guided --format sarif         # AI harness

# run the built-in case library and check against ground truth
python -m aifuzz.cli suite
```
> Echidna runs inside the Docker image, so CLI analysis expects the compose stack to be up
> (`docker compose up -d`).

---

## Reproducing the AI-vs-random comparison

The held-out evaluation over the full test set (produces the paper's numbers and figures):

```bash
python benchmark_testset.py --approach random     # baseline (A): template harness, random inputs
python benchmark_testset.py --approach ai-seed    # B1: same harness, LLM+RAG seeded inputs
python benchmark_testset.py --approach ai-seed-cot # B1-CoT: as B1, but the model plans before it emits
python benchmark_testset.py --approach ai         # B2: LLM-authored harness, random inputs
python benchmark_testset.py --approach ai-full    # B3: LLM harness + LLM inputs

python make_figures.py           # confusion matrices + comparison charts → eval_results/
python make_report.py            # metrics table + summary                → eval_results/
python metric_justification.py   # why precision/recall/F1, not accuracy
python progress.py               # live progress while a run is in flight
```

Each run appends to `eval_out/results.jsonl` and **resumes from it** — a contract already
recorded for an arm is skipped, so an interrupted sweep can simply be restarted. To force an arm
to run again, remove its rows from that file first. Figures and tables go to `eval_results/`.
Both directories are git-ignored and regenerated per run.

Add `--limit N` for a quick smoke test across a spread of classes before committing to a full
sweep; a complete arm takes hours, dominated by LLM generation in the AI arms.

---

## Layout

```
aifuzz/            the Python package — one responsibility per module:
  ── fuzzing ──
    synthesize.py    auto-builds the Echidna harness: ABI forwarders + per-shape oracles
    fuzzer.py        runs Echidna (in Docker); parses findings + target-line coverage
    analyzer.py      orchestrates one analysis (random / ai-seed / ai-guided)
    local_chain.py   local Anvil chain for deploy / proof-of-concept exploits
  ── AI / retrieval ──
    ai_guidance.py   RAG: embeds the contract, retrieves neighbours (ChromaDB), prompts the LLM
    config.py        all settings, env-driven (model, embedder, paths) — nothing hardcoded
  ── output ──
    report.py        findings → JSON / Markdown / SARIF
    suite.py         runs the labelled case library and checks vs ground truth
    cli.py           command-line entry point (analyze / deploy / suite / benchmark)

dashboard/         Flask web UI (upload, mode, verdict + proof + harness)
examples/          standalone contracts to try the tool immediately, no corpus needed
tests/             pytest suite, contract fixtures, and the `aifuzz suite` case library
  fixtures/          contracts used only as test targets (+ labels.csv, provenance)
  harnesses/         hand-written Echidna harnesses + registry.yaml
dataset/           where you download the Hugging Face reference corpus (git-ignored; see Setup)
Dockerfile / docker-compose.yml   the stack: aifuzz app + Ollama sidecar + persisted vector store
reference-paper.pdf   IEEE reference paper (evaluation methodology)

-- evaluation scripts (repo root) --
benchmark_testset.py    runs one arm (A / B1 / B2 / B3) over the held-out test set
run_arm.sh              wrapper for the above: sets the budget, logs, and locks per arm
make_figures.py         confusion matrices + comparison charts   -> eval_results/
make_report.py          metrics table + written summary          -> eval_results/
metric_justification.py derives why precision/recall/F1 are reported rather than accuracy
progress.py             live progress while a sweep is in flight
```

### What each directory is for

Four directories, each with one job. Nothing else is committed.

| Directory | Purpose | Needed to run the tool? |
|---|---|---|
| `aifuzz/` | The tool: harness synthesis, fuzzing, RAG, reporting, CLI | Yes |
| `dashboard/` | Flask UI over the same `analyze()` entry point the CLI uses | Only for the web UI |
| `examples/` | Five self-contained contracts to try it without downloading the corpus | No, convenience |
| `tests/` | `pytest` suite, `fixtures/` targets, and `harnesses/` + `registry.yaml` for `aifuzz suite` | No, development |

Three more directories appear once you run the tool. All are git-ignored, because each is
downloaded or generated rather than authored:

| Directory | Created by | Holds |
|---|---|---|
| `dataset/` | you, in Setup Step 3 | the Hugging Face reference corpus |
| `chroma_data/` | first AI-mode run | the vector index built from `dataset/` |
| `eval_out/`, `eval_results/` | `benchmark_testset.py`, `make_figures.py` | raw results, figures, tables |

A fresh clone therefore contains code and documentation only.

**Where the pieces live** (per the design's separation of concerns):
- **Fuzzing** is `synthesize.py` + `fuzzer.py` + `analyzer.py`.
- **Embedding / retrieval** is `ai_guidance.py` + `config.py`; the vector index is the git-ignored
  `chroma_data/`, built from the reference corpus you download.
- **The reference-set contracts themselves are not in this repo** — the full labelled corpus is a
  separate dataset on Hugging Face (download it into `dataset/`, see Setup Step 3). There is no
  bundled sample: a fresh clone has no reference data, so the AI starts with an empty index.

---

## Dataset

The full labelled benchmark corpus is hosted on **Hugging Face**:
[`Ai-Fuzz/smart-contracts`](https://huggingface.co/datasets/Ai-Fuzz/smart-contracts). It is split
into a **reference** set (what you embed for retrieval) and a **held-out test** set (what the
evaluation measures), with leakage controlled by near-duplicate deduplication so a test contract's
near-copies can never appear on the reference side. Provenance and licences are on the dataset card.

**Reproducing the paper's numbers requires this dataset** — see Setup Step 3 to download and embed
it. Without it the AI modes run but retrieve nothing.

Vulnerability classification follows the **EEA EthTrust Security Levels Specification v3**, the only
actively-maintained smart-contract conformance standard among those evaluated (SWC is deprecated;
CWE is language-agnostic; DASP is a 2018 snapshot).

---

## Configuration

Everything is env-driven via `.env` (copied from `.env.example`) — no hardcoded versions, models,
or chain names. Key settings: `OLLAMA_MODEL` (generator, default `qwen2.5-coder:7b`), `EMBED_MODEL`
(embedder, default `nomic-embed-text`), `RAG_CORPUS_DIR` (folder of reference contracts to embed —
`dataset/`, which you populate from Hugging Face; see Setup Step 3), `ECHIDNA_TEST_LIMIT`,
`SOLC_VERSION`, `PORT`.

**Requirements:** Docker Desktop. The AI modes additionally need the pulled model (~4.7 GB) and,
for the LLM, ~6 GB VRAM at 4-bit quantisation (runs on CPU too, slower).

**Tested on:** Windows 11 (Docker Desktop), macOS 14 (Docker Desktop).

## Tests

```bash
pytest
```

---

## Licence

**AGPL-3.0-or-later.** Full text in [`LICENSE`](LICENSE).

This is not an arbitrary choice. `aifuzz` imports [Slither](https://github.com/crytic/slither)
directly (`aifuzz/synthesize.py`) and drives [Echidna](https://github.com/crytic/echidna) and
`crytic-compile`, all of which are AGPL-3.0. A permissive licence on the combined work would
conflict with their terms, so this project matches them.

Practical consequence: if you modify `aifuzz` and run it as a network service — the Flask
dashboard included — AGPL section 13 requires you to offer users the corresponding source.

| Component | Licence | Relationship |
|---|---|---|
| `aifuzz` (this repo) | AGPL-3.0-or-later | — |
| Slither, crytic-compile, solc-select | AGPL-3.0 | imported / invoked |
| Echidna | AGPL-3.0 | invoked in the Docker image |
| Qwen2.5-Coder-7B, nomic-embed-text | Apache-2.0 | model weights, pulled at runtime |
| ChromaDB, Flask, PyYAML | Apache-2.0 / BSD | libraries |

The evaluation corpus is a **separate artifact under its own terms** — see the dataset card on
Hugging Face. Code and data licences are independent; neither implies the other.
