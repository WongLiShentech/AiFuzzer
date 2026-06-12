// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ORACLE-MANIPULATION model (Mechanism A, minimal & self-contained).
//
// The real Damn Vulnerable DeFi Puppet pools (dataset/vulnerable/oracle-
// manipulation/) import Uniswap + OpenZeppelin and only compile from the full
// DVD project, so they cannot be fuzzed as standalone files (see that folder's
// DEPENDENCY_NOTE.md). Oracle-manipulation is also not a self-contained bug: it
// lives in a contract's RELATIONSHIP with a price source it does not control.
//
// This harness isolates the class the way the M3 AI will generalise it: the
// price source is a FUZZABLE INPUT (setPrice), and the oracle is the pool's
// solvency invariant. If some price lets borrowed value exceed the HONEST value
// of the collateral, the pool can be drained -- that is oracle-manipulation,
// proven by fuzzing rather than pattern-matched. Inputs are bounded (modulo) so
// the search space is small and arithmetic cannot overflow.

contract OracleManipEchidnaTest {
    uint256 constant HONEST_PRICE = 100;   // true ETH value per unit of collateral
    uint256 public price = HONEST_PRICE;   // the manipulable on-chain price source

    uint256 public totalCollateral;        // units of collateral deposited
    uint256 public totalDebt;              // ETH value borrowed against it

    // The vulnerable dependency: the price an attacker can move (e.g. a DEX spot
    // price or an unguarded feed). Bounded so collateral*price cannot overflow.
    function setPrice(uint256 p) public {
        price = p % 1_000_000;
    }

    function deposit(uint256 amount) public {
        totalCollateral += amount % 1_000;
    }

    // BUG: collateral is valued at the manipulable spot `price`, not an honest one.
    function borrow(uint256 amount) public {
        uint256 b = amount % 1_000_000;
        require(totalDebt + b <= totalCollateral * price, "undercollateralized");
        totalDebt += b;
    }

    // ORACLE: total debt must never exceed the HONEST value of the collateral.
    // Manipulating `price` upward lets borrowing exceed collateral*HONEST_PRICE,
    // which breaks this -> the pool is insolvent -> oracle-manipulation.
    function echidna_pool_stays_solvent() public view returns (bool) {
        return totalDebt <= totalCollateral * HONEST_PRICE;
    }
}
