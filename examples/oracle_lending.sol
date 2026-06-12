pragma solidity ^0.8.0;

// DEMO upload for the ORACLE-MANIPULATION recognition path. A settable `price`
// used in a borrow check is a textbook oracle-manipulation surface. The tool
// RECOGNISES it but honestly declines to fake a market harness:
//   "Recognised an oracle-manipulation surface ... that synthesis is the M3 AI step."
// This is the limit of templating and exactly what the M3 AI is for.
contract LendingPool {
    uint256 public price = 100;     // a manipulable on-chain price source
    uint256 public collateral;

    function setPrice(uint256 p) public { price = p; }
    function deposit(uint256 amount) public { collateral += amount; }

    function borrow(uint256 amount) public {
        require(amount <= collateral * price, "undercollateralized");
    }
}
