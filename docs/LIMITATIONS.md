# Limitations and Honest Scope

A deliberate account of what this tool does *not* do and where its results must
be read with care. Stating limits plainly is part of doing security work
honestly; absence of a finding is never a proof of safety.

## Fuzzing is incomplete by nature
Fuzzing *samples* the space of transaction sequences; it does not exhaustively
explore it. A clean result ("0 findings") means the fuzzer did not find a
violating sequence within its budget, **not** that the contract is safe. Bugs
that require a long, precise sequence or rare input may be missed. This is
inherent to all fuzzing (Echidna, Foundry, etc.), not specific to this tool.

## The AI operates in the outer loop, not per transaction
An LLM cannot run inside the per-transaction fuzzing loop: a campaign executes
tens of thousands of transactions, and an LLM call takes hundreds of
milliseconds to seconds, so per-step LLM guidance is computationally infeasible.
The AI (M3) therefore works at the outer loop -- reading the contract once and
emitting invariants, seed sequences, and a value dictionary that prime the
fuzzer. This is the realistic and standard way to combine LLMs with fuzzing.

## Harness generation is template-based, not yet AI
The tool now auto-generates a harness (attacker + `echidna_*` invariant) from a
raw contract for the shapes it recognises — a balance-ledger reentrancy pool, a
privileged-owner access-control pattern, and a reward-claim ordering pattern —
using Slither semantic detection with a regex fallback, and emits one harness per
matched shape (`aifuzz/synthesize.py`). These templates are non-AI. Generating a
harness (and the surrounding environment, e.g. a market for oracle manipulation)
for an *arbitrary* contract is the M3 deliverable and the project's novelty;
hand-written harnesses remain only for the curated evaluation suite.

## Finding metadata is partially fixed
Every Echidna finding is currently labelled severity HIGH and rule
`invariant-violation`, and no source line is extracted. The *existence* of a
finding, the violated property name, and the triggering transaction sequence are
computed live from Echidna; the severity/rule/line fields are constant labels or
unset. Per-vulnerability severity and source-line mapping are future work.

## Dataset coverage is uneven, by source availability
The clean (true-negative) set is smaller than the vulnerable set and does not
cover every vulnerability type. In particular, no safe transaction-ordering
(TOD) contract exists in any of the four cited source repositories, so that
class is represented by positive samples only. This is documented in
`tests/fixtures/DATASET_PROVENANCE.md`. Clean contracts were never fabricated to force
a balanced count -- an honest uneven set is preferred over a balanced synthetic
one, since fabricated contracts would void the dataset's provenance.

## Some vulnerability classes are hard to harness standalone
Oracle-manipulation contracts (the Damn Vulnerable DeFi Puppet pools) depend on
external protocols (Uniswap-style DEXs) and cannot be fuzzed as isolated files.
A faithful harness for them is substantial work and is a candidate for the
AI-generation stage rather than manual harnessing.

## Internal EVM vs. a real chain
Fuzzing runs in Echidna's internal EVM (hevm), not on the Anvil local chain.
Both implement the EVM specification, so a bug found in hevm is a real EVM bug;
differences (precise gas, certain precompiles, mainnet-forked state) are not
relevant to the vulnerability classes in scope. The Anvil local chain is used
for deployment and proof-of-concept exploits, not for the fuzzing loop.

## Evaluation: AI column pending
`benchmark.py` reports bugs found, Precision/Recall/F1/FPR, **code coverage, run
time, and a composite score** across multiple trials. Coverage + time are now
parsed from Echidna's output and wired end to end (report -> dashboard ->
benchmark). The AI-guided column stays "pending (M3)" until the AI engine lands;
PoC exploits on the Anvil chain are future work.
