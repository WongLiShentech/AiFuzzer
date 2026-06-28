# Example uploads — Tier-2 auto-synthesis demo

Drop any of these into the dashboard (or run `aifuzz analyze <file> --auto`) to see
the tool read a **raw** contract, synthesise a harness from its structure (no AI),
and fuzz it. This is the pre-M3 baseline: it covers the shapes a template can
recognise, and honestly defers the rest to the M3 AI.

| Upload | Path exercised | Expected result |
|---|---|---|
| `../tests/fixtures/vulnerable/reentrancy/simple_dao.sol` | reentrancy (`withdraw(amount)`) | **VULNERABLE** |
| `reentrancy_withdraw_all.sol` | reentrancy (`withdraw()` drains all) | **VULNERABLE** |
| `access_control_unprotected.sol` | access control (public owner) | **VULNERABLE** |
| `access_control_safe.sol` | access control (guarded) | **NO VULNERABILITIES** (no false positive) |
| `../tests/fixtures/vulnerable/access-control/Unprotected.sol` | access control (private owner, guarded-twin probe) | **VULNERABLE** |
| `../tests/fixtures/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol` | ordering / TOD | **VULNERABLE** |
| `multi_vuln_bank.sol` | reentrancy + access control (one contract, two shapes) | **VULNERABLE** (two findings) |
| `oracle_lending.sol` | oracle manipulation | **Recognised, deferred to M3** (no faked harness) |

Out of scope (honest skip): contracts whose only bug is **not** one of the four
target types — e.g. integer overflow or weak randomness — return "could not
recognise this shape (needs M3)". That is correct: they aren't in the EEA focus set.

How it works: `aifuzz/synthesize.py` matches the contract's structure against known
vulnerability shapes (a balance ledger + external send = reentrancy; a public owner
+ unguarded setter = access control; a payable prize funder + a claim that pays the
caller = ordering). It generates a harness with the right oracle and attacker, then
Echidna decides VULNERABLE vs CLEAN. The oracle-manipulation surface is *recognised*
but not auto-harnessed — a faithful market (DEX + tokens + pool) can't be
reconstructed from source by a template; that is what the M3 AI adds.
