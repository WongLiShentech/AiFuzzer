# Dataset Provenance

**Project:** AI-Assisted Fuzzing Framework for Smart Contract Security
**Institution:** Singapore Institute of Technology (SIT) — IWL2
**Supervisor:** Prof Purnima Mohan
**Compiled:** 2026-06-09

This document records the origin, licensing, and academic justification for
every smart contract in `D2-testing-environment/dataset/`. All contracts are
unmodified Solidity sourced from publicly available repositories; the only
addition to each file is a leading metadata comment block recording its
provenance and ground-truth label. The machine-readable index is
`labels.csv`, regenerated from these metadata blocks by `generate_labels.py`.

The dataset covers the four vulnerability types in scope for this project,
aligned to the **EEA EthTrust Security Levels v3** specification:

| # | Vulnerability type | EEA EthTrust v3 section |
|---|--------------------|--------------------------|
| 1 | Reentrancy (incl. cross-function) | Section 3.4 — External Interactions and Re-entrancy Attacks |
| 2 | Oracle Manipulation | Section 3.3 — External Data / Oracle Manipulation |
| 3 | Ordering Attacks (Front-Running / TOD) | Section 3.8 — Transaction Ordering Dependence |
| 4 | Access Control (incl. `tx.origin` authorization) | Section 5 — Access Control |

---

## 1. Source repositories

| Source repository | GitHub URL | Academic / authoritative citation | Licence | Contracts taken |
|-------------------|-----------|-------------------------------------|---------|-----------------|
| SmartBugs Curated | https://github.com/smartbugs/smartbugs-curated | Durieux, T., Ferreira, J. F., Abreu, R., Cruz, P. (2020). *Empirical Review of Automated Analysis Tools on 47,587 Ethereum Smart Contracts.* ICSE 2020. | Apache-2.0 | 9 |
| Not So Smart Contracts (Trail of Bits) | https://github.com/crytic/not-so-smart-contracts | Trail of Bits. *(Not So) Smart Contracts* — curated examples of common Solidity security issues. | Apache-2.0 | 1 |
| SWC Registry | https://github.com/SmartContractSecurity/SWC-registry | Wagner, G. et al. *Smart Contract Weakness Classification and Test Cases Registry (SWC).* (Archived 2020; superseded by EEA EthTrust SL.) | MIT | 4 |
| Damn Vulnerable DeFi | https://github.com/theredguild/damn-vulnerable-defi | Rodríguez, T. (tinchoabbate). *Damn Vulnerable DeFi* — offensive security wargame for DeFi smart contracts. | MIT | 2 |
| **Total** | | | | **16** |

> **Note on SWC Registry retrieval.** The SWC Registry was archived in 2020 and
> has since been converted to a documentation-only repository; the original
> `test_cases/` `.sol` files no longer exist as standalone files. The four SWC
> contracts below were extracted **verbatim** from the named code samples still
> embedded in `entries/docs/SWC-107.md` and `entries/docs/SWC-115.md`. Filenames
> and contents are unchanged from the original test cases.

---

## 2. Per-contract provenance

### Reentrancy — `vulnerable/reentrancy/` (label = 1, EEA §3.4)

| File | Source repo | EEA section | Reason for selection |
|------|-------------|-------------|----------------------|
| `simple_dao.sol` | SmartBugs Curated | §3.4 | Canonical SimpleDAO (Atzei et al.) with an external call before the credit state update — the pattern behind the 2016 DAO hack. |
| `etherstore.sol` | SmartBugs Curated | §3.4 | Widely cited EtherStore teaching contract; state is updated after the external call in the withdraw path. |
| `0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol` | SmartBugs Curated | §3.4 | A real deployed mainnet contract, supplying an authentic (non-synthetic) in-the-wild positive sample. |

### Oracle Manipulation — `vulnerable/oracle-manipulation/` (label = 1, EEA §3.3)

| File | Source repo | EEA section | Reason for selection |
|------|-------------|-------------|----------------------|
| `PuppetPool.sol` | Damn Vulnerable DeFi | §3.3 | Lending pool that prices collateral from a manipulable DEX spot price — the archetypal single-source oracle manipulation. |
| `PuppetV2Pool.sol` | Damn Vulnerable DeFi | §3.3 | v2 pool relying on a Uniswap v2 spot-price oracle, vulnerable to flash-loan price manipulation. |

### Ordering Attacks (Front-Running / TOD) — `vulnerable/ordering-attacks/` (label = 1, EEA §3.8)

| File | Source repo | EEA section | Reason for selection |
|------|-------------|-------------|----------------------|
| `ERC20.sol` | SmartBugs Curated | §3.8 | ERC20 approve/transferFrom allowance race — the classic transaction-ordering hazard in token approvals. (Same canonical contract as SWC-114's `ERC20.sol`.) |
| `eth_tx_order_dependence_minimal.sol` | SmartBugs Curated | §3.8 | Minimal reward-claim contract whose payout depends on transaction ordering. (Same canonical contract as SWC-114's TOD sample.) |
| `FindThisHash.sol` | SmartBugs Curated | §3.8 | Hash-puzzle reward contract vulnerable to front-running of the winning-solution submission. |
| `odds_and_evens.sol` | SmartBugs Curated | §3.8 | Two-player wager whose outcome can be manipulated via mempool observation and transaction ordering. |

### Access Control — `vulnerable/access-control/` (label = 1, EEA §5)

| File | Source repo | EEA section | Reason for selection |
|------|-------------|-------------|----------------------|
| `parity_wallet_bug_1.sol` | SmartBugs Curated | §5 | Parity multisig wallet (first bug): an unprotected initialization function allowed arbitrary ownership takeover. |
| `parity_wallet_bug_2.sol` | SmartBugs Curated | §5 | Parity multisig wallet (second bug): an unprotected library self-destruct froze ~150M USD of user funds. |
| `Unprotected.sol` | Not So Smart Contracts | §5 | Minimal example of a state-changing function missing an access-control modifier, isolating the unprotected-function pattern. |
| `mycontract.sol` | SWC Registry (SWC-115) | §5 ([S] No `tx.origin`) | Consensys Diligence canonical `tx.origin` authorization example; authorizing on `tx.origin` enables phishing via an intermediary contract. |

### Clean / true-negative controls — `clean/` (label = 0)

| File | Source repo | EEA section | Reason for selection |
|------|-------------|-------------|----------------------|
| `simple_dao_fixed.sol` | SWC Registry (SWC-107) | §3.4 (remediated) | Remediated SimpleDAO applying checks-effects-interactions; true-negative reentrancy control. |
| `modifier_reentrancy_fixed.sol` | SWC Registry (SWC-107) | §3.4 (remediated) | Remediated modifier-ordering contract; true-negative control for modifier-based reentrancy. |
| `mycontract_fixed.sol` | SWC Registry (SWC-115) | §5 (remediated) | Remediated contract using `msg.sender` for authorization; true-negative control for the `tx.origin` class. |

Clean contracts (label = 0) are required to compute the **False Positive Rate
(FPR)** reported in Tables 5 and 6 of the reference paper.

---

## 3. Oracle-manipulation OpenZeppelin dependency

The contracts in `vulnerable/oracle-manipulation/` (`PuppetPool.sol`,
`PuppetV2Pool.sol`) import OpenZeppelin and project-internal contracts. They
**must not** be analysed as standalone files. Slither (and other analysers) must
be run from the Damn Vulnerable DeFi project root so dependencies and import
remappings resolve. The pipeline handles this automatically. See
`vulnerable/oracle-manipulation/DEPENDENCY_NOTE.md`.

> Upstream note: Damn Vulnerable DeFi has migrated from Hardhat to **Foundry**.
> The Puppet contracts now live under `src/puppet/` and `src/puppet-v2/` (not
> `contracts/`), and the project root is a Foundry project. The dependency
> principle is unchanged — analyse from the project root with dependencies
> resolved, never per-file.

---

## 4. Deviations from the original collection plan

For full transparency, two items in the original collection plan could not be
satisfied because upstream repositories were restructured after the plan was
written:

1. **`not-so-smart-contracts/front_running/ERC20.sol`** — the `front_running/`
   directory no longer exists upstream (the repository was reorganised; only
   `race_condition/RaceCondition.sol` remains). This slot was **skipped**: the
   identical ERC20 approval/front-running vulnerability class is already
   represented by SmartBugs Curated's `ERC20.sol`.
2. **Clean / safe transaction-order-dependence contract** — SWC-114 provides
   only vulnerable samples; no safe TOD contract exists in any of the four
   sources. This slot was **skipped**. The clean set therefore covers reentrancy
   (×2) and `tx.origin` (×1); TOD is represented by positive samples only.

---

## 5. Academic use statement

All smart contracts in this dataset are publicly available, open-source
material (Apache-2.0 and MIT licences, as recorded above). They are reproduced
here unmodified — apart from a non-executable leading metadata comment block —
solely for **non-commercial academic research** in partial fulfilment of the
SIT IWL2 module. Original authorship and licences are retained in each file and
credited above. No proprietary, confidential, or production credential material
is included.
