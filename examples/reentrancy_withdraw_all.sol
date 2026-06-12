pragma solidity ^0.4.15;

// DEMO upload exercising the "withdraw-everything" reentrancy variant: the
// withdraw function takes NO amount argument (it drains the caller's full
// balance), and sends ETH before zeroing the ledger. `--auto` (or the dashboard
// upload) synthesises a reentrancy harness and reports VULNERABLE.
contract Reentrance {
    mapping (address => uint) userBalance;

    function getBalance(address u) constant returns(uint) { return userBalance[u]; }

    function addToBalance() payable { userBalance[msg.sender] += msg.value; }

    function withdrawBalance() {
        // sends ETH before updating state -> re-entrant drain
        if (!(msg.sender.call.value(userBalance[msg.sender])())) { throw; }
        userBalance[msg.sender] = 0;
    }
}
