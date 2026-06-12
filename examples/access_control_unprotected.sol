pragma solidity ^0.4.24;

// DEMO upload for the ACCESS-CONTROL auto-synthesis path.
// A public `owner` with an UNGUARDED setter: any account can seize ownership.
// `aifuzz analyze examples/access_control_unprotected.sol --auto` (or dropping it
// in the dashboard) synthesises an access-control harness and reports VULNERABLE.
contract Wallet {
    address public owner;

    function Wallet() public { owner = msg.sender; }

    // Missing access control — should require(msg.sender == owner).
    function setOwner(address newOwner) public {
        owner = newOwner;
    }
}
