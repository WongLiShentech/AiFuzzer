pragma solidity ^0.4.15;

// ACCESS-CONTROL oracle (Mechanism A) wrapping a REAL dataset contract:
// tests/fixtures/vulnerable/access-control/Unprotected.sol — Trail of Bits' minimal
// "unprotected function" example whose changeOwner() lacks an onlyowner guard,
// so ANY account can seize ownership.
//
// Unprotected.owner is `private` (no getter), so we can't read it directly.
// Instead we PROBE ownership through the contract's OWN guarded twin,
// changeOwner_fixed() (which is `onlyowner`): a low-level call to it succeeds
// only while the caller is still the owner. The harness deploys Unprotected
// (becoming its owner), then an Attacker — a NON-owner — calls the unguarded
// changeOwner() to seize control. Reusable rule: "ownership must never move to
// an account that was never authorised."
import "../tests/fixtures/vulnerable/access-control/Unprotected.sol";

contract Attacker {
    // A non-owner that grabs ownership via the unguarded setter.
    function seize(Unprotected u) public {
        u.changeOwner(this);
    }
}

contract AccessControlEchidnaTest {
    Unprotected public vault;
    Attacker public attacker;

    function AccessControlEchidnaTest() public {
        vault = new Unprotected();   // owner := this harness (the deployer)
        attacker = new Attacker();
    }

    // Let the (non-owner) attacker grab ownership through the unguarded function.
    function attack() public {
        attacker.seize(vault);
    }

    // ORACLE: the original owner (this harness) must always be able to exercise
    // an owner-only function. We probe via the contract's guarded
    // changeOwner_fixed(): the low-level call succeeds (returns true) only while
    // WE are still the owner. Once the attacker has seized ownership the guard
    // reverts and this returns false -> Echidna reports the violation + sequence.
    function echidna_owner_retained() public returns (bool) {
        return address(vault).call(
            bytes4(keccak256("changeOwner_fixed(address)")), address(this)
        );
    }
}
