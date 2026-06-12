pragma solidity ^0.4.24;

// DEMO upload showing the auto-synthesis path does NOT false-positive: same shape
// as access_control_unprotected.sol but the setter is properly guarded, so the
// synthesised attacker's call reverts and ownership never moves -> NO VULNS FOUND.
contract SafeWallet {
    address public owner;

    function SafeWallet() public { owner = msg.sender; }

    function setOwner(address newOwner) public {
        require(msg.sender == owner);   // proper access control
        owner = newOwner;
    }
}
