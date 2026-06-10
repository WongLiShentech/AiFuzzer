// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// First-slice Echidna harness (M2) — a deliberately vulnerable contract plus an
// invariant Echidna should be able to break by random transaction generation.
//
// Vulnerability class: ACCESS CONTROL.
// `setOwner` has no `onlyOwner` / `msg.sender` guard, so ANY account can seize
// ownership. Chosen for the first slice because Echidna can break it with a
// single direct call (no attacker contract needed) — it proves the analyze →
// fuzz → finding → report loop works. A reentrancy harness (needing a malicious
// callback + value config) is the next step.

contract VulnerableVault {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // BUG: missing access control — anyone can take ownership.
    function setOwner(address newOwner) public {
        owner = newOwner;
    }
}

// Echidna test contract. Echidna deploys this and fuzzes its inherited
// functions from several sender accounts. The property below must always hold;
// the missing guard on setOwner() lets Echidna falsify it.
contract AccessControlEchidnaTest is VulnerableVault {
    address private immutable deployer;

    constructor() {
        deployer = msg.sender;
    }

    // INVARIANT: ownership must never move away from the deployer.
    // Echidna will call setOwner(<someAddr>) and break this — reporting the
    // exact transaction sequence that did it.
    function echidna_owner_is_deployer() public view returns (bool) {
        return owner == deployer;
    }
}
