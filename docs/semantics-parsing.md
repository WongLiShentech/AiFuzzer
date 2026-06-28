# Semantics: parsing contracts instead of pattern-matching them

## What "semantics" means here

To build a harness for an uploaded contract, the tool first has to *understand*
the contract — which functions exist, what state they touch, where the external
calls are. Today `aifuzz/synthesize.py` does this with **regex** (text matching).
Regex reads the surface syntax, not the meaning, so it is brittle:

- it breaks on newer Solidity (e.g. 0.6+ `call{value: x}("")` instead of the old
  `call.value(x)()`),
- it cannot follow control flow or data flow,
- it can miss a function written in an unusual but equivalent way.

**Semantics = understanding the contract's actual structure by parsing it into an
AST (Abstract Syntax Tree)** rather than scanning text. The AST is the compiler's
own structured view: functions, parameters, modifiers, state variables, and the
calls between them.

## Proposal

Move shape detection from regex to AST-based parsing, using tools already in our
Docker image:

- `crytic-compile` — Echidna's own compiler frontend (gives a normalized
  compilation + AST),
- Slither's intermediate representation (built on crytic-compile), or
- `solc --ast-compact-json` (the compiler's raw AST).

Why it is worth it:
1. **Robust, version-agnostic detection** — find a "deposit / withdraw with an
   external send" by structure, not by a fragile string.
2. **Foundation for the AI (M3)** — embeddings and AI harness generation work on
   a parsed, normalized representation of the contract, not raw text. Parsing is
   the bridge from the current regex Tier-2 to the AI step.

## What shape detection does — and does not — decide

Shape detection classifies by **shape**, i.e. *which harness to build* (or none).
It does **not** decide vulnerable vs clean — the fuzzer does that. So there are
three outcomes for any contract:

| Outcome | Meaning |
|---|---|
| shape matched, oracle broken | **VULNERABLE** |
| shape matched, oracle holds | **CLEAN** (a harness was still generated) |
| no shape matched | **SKIPPED** (needs the AI step) |

This is why a clean contract with a known shape (e.g. `simple_dao_fixed`) still
gets a harness and is *proven* clean by fuzzing — which avoids the false positives
a static "looks like reentrancy" check would make.

## Granularity

Harness generation is **per contract** (bespoke — built from the contract's own
function names), and now emits **one harness per applicable vuln type**, so a
contract that matches two shapes is fuzzed for both. The remaining generalization
— understanding shapes the templates do not cover — is exactly what the AST
parsing and the AI provide.
