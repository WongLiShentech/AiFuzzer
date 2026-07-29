# Example contracts

Self-contained contracts for trying the tool without downloading the reference corpus. Drop one
into the dashboard, or run:

```bash
python -m aifuzz.cli analyze examples/reentrancy_withdraw_all.sol --auto --mode random
```

The tool reads the raw contract, synthesises a harness from its structure, and fuzzes it. No AI
is involved in `--mode random`, so all of these work on a fresh clone.

| Contract | Shape | Verdict |
|---|---|---|
| `reentrancy_withdraw_all.sol` | reentrancy — sends before zeroing the balance | **Reentrancy** |
| `multi_vuln_bank.sol` | reentrancy plus an unguarded owner setter | **Reentrancy** |
| `access_control_safe.sol` | access control, correctly guarded | clean (no false positive) |
| `access_control_unprotected.sol` | ownership hijack via an unguarded setter | clean — see below |
| `oracle_lending.sol` | price-dependent lending | clean — see below |

Verdicts measured with `--mode random` on the current build.

## Two contracts that report clean, and why

`access_control_unprotected.sol` contains a genuine ownership-hijack bug and the tool does not
flag it. This is a deliberate limitation rather than an oversight. An `owner unchanged` invariant
cannot distinguish a protected owner from an address field that is settable by design — a fee
recipient or an operator slot — so that oracle was implemented, measured, found to catch none of
the real misses while adding false positives on clean contracts, and removed. Access-control
detection is consequently limited to two shapes it can assert safely: an unprotected
`selfdestruct`, and an attacker extracting ether it never deposited. See
[`../docs/LIMITATIONS.md`](../docs/LIMITATIONS.md).

`multi_vuln_bank.sol` carries two weaknesses and only the reentrancy is reported, for the same
reason.

`oracle_lending.sol` has a price-manipulation surface, but a faithful market — DEX, tokens, pool
— cannot be reconstructed from a single source file by a template, so no harness is synthesised
for that shape. It is included to show where the boundary lies, not to demonstrate a detection.

## Out of scope

Contracts whose only defect falls outside the four target classes — integer overflow, weak
randomness, unchecked return values — are reported as an unrecognised shape rather than guessed
at. That is intended: the tool speaks only to reentrancy, access control, ordering attacks, and
oracle manipulation.

## How the harness is built

`aifuzz/synthesize.py` matches the contract's structure against known vulnerability shapes — a
balance ledger plus an external send is reentrancy; a payable prize funder plus a claim that pays
the caller is an ordering attack — then emits a harness carrying the matching `echidna_*`
invariant and, where needed, an attacker contract. Echidna decides the verdict by trying to
falsify that invariant.
