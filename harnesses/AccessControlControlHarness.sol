pragma solidity 0.4.25;

// ACCESS-CONTROL true-negative control (Mechanism A) wrapping a REAL clean
// dataset contract: tests/fixtures/clean/mycontract_fixed.sol (GROUND_TRUTH_LABEL = 0)
// -- the SWC-115 remediation that authorises on msg.sender instead of tx.origin.
//
// Mirror of AccessControlHarness: an Attacker (a NON-owner) tries to invoke the
// owner-only function. On this remediated contract the msg.sender guard always
// blocks it, so authority never leaks: 0 findings, no false alarm. The same
// probe on a BUGGY contract (an unguarded setter) WOULD succeed -- which is what
// makes this a meaningful control rather than a trivial pass.
import "../tests/fixtures/clean/mycontract_fixed.sol";

contract Attacker {
    // Attempt the owner-only function as a non-owner. Low-level call so the
    // guard's revert comes back as `false` instead of bubbling up and aborting.
    function tryUse(MyContract m) public returns (bool) {
        return address(m).call(
            bytes4(keccak256("sendTo(address,uint256)")), address(this), uint256(0)
        );
    }
}

contract AccessControlControlEchidnaTest {
    MyContract public myc;
    Attacker public attacker;
    bool internal breached;

    function AccessControlControlEchidnaTest() public {
        myc = new MyContract();      // owner := this harness (the deployer)
        attacker = new Attacker();
    }

    // The non-owner attacker repeatedly tries the guarded function.
    function attack() public {
        if (attacker.tryUse(myc)) {
            breached = true;   // only flips if the guard ever lets a non-owner through
        }
    }

    // CLEAN ORACLE: a non-owner must never succeed at the owner-only function.
    // The remediated contract holds the line, so this stays true: 0 findings.
    function echidna_no_unauthorized_access() public view returns (bool) {
        return !breached;
    }
}
