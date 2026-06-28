pragma solidity ^0.4.24;

// DEMO upload showing MULTI-TYPE detection: this contract has TWO shapes at once
// — a deposit/withdraw reentrancy pool AND a public owner with an unguarded
// setter (access control). `--auto` now synthesises a harness for EACH and
// fuzzes both, so the report shows two findings (reentrancy + access-control).
contract Bank {
    mapping(address => uint) balances;
    address public owner;

    function Bank() public { owner = msg.sender; }

    function deposit() public payable { balances[msg.sender] += msg.value; }

    function withdraw() public {                    // reentrancy: sends before zeroing
        if (!msg.sender.call.value(balances[msg.sender])()) { throw; }
        balances[msg.sender] = 0;
    }

    function setOwner(address n) public { owner = n; }   // access control: no guard
}
