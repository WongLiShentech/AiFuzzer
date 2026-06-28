/*
 * DATASET_SOURCE: https://github.com/SmartContractSecurity/SWC-registry/blob/master/entries/docs/SWC-107.md (sample "simple_dao_fixed.sol"; originally test_cases/reentrancy/simple_dao_fixed.sol)
 * VULNERABILITY_TYPE: none
 * EEA_ETHTRUST_V3_SECTION: Section 3.4 - External Interactions and Re-entrancy Attacks (remediated)
 * GROUND_TRUTH_LABEL: 0
 * ACADEMIC_BASIS: SWC-107 remediated SimpleDAO applying checks-effects-interactions; true-negative reentrancy control for measuring false positive rate.
 * ORIGINAL_LICENSE: MIT (SWC Registry)
 */

/*
 * @source: http://blockchain.unica.it/projects/ethereum-survey/attacks.html#simpledao
 * @author: Atzei N., Bartoletti M., Cimoli T
 * Modified by Bernhard Mueller, Josselin Feist
 */
pragma solidity 0.4.24;

contract SimpleDAO {
  mapping (address => uint) public credit;

  function donate(address to) payable public{
    credit[to] += msg.value;
  }

  function withdraw(uint amount) public {
    if (credit[msg.sender]>= amount) {
      credit[msg.sender]-=amount;
      require(msg.sender.call.value(amount)());
    }
  }

  function queryCredit(address to) view public returns (uint){
    return credit[to];
  }
}
