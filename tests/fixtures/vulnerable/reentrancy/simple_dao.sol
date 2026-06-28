/*
 * DATASET_SOURCE: https://github.com/smartbugs/smartbugs-curated/blob/main/dataset/reentrancy/simple_dao.sol
 * VULNERABILITY_TYPE: Reentrancy
 * EEA_ETHTRUST_V3_SECTION: Section 3.4 - External Interactions and Re-entrancy Attacks
 * GROUND_TRUTH_LABEL: 1
 * ACADEMIC_BASIS: Canonical SimpleDAO example (Atzei et al.) showing an external call before the credit state update, the pattern behind the 2016 DAO hack.
 * ORIGINAL_LICENSE: Apache-2.0 (SmartBugs Curated)
 */
/*
 * @source: http://blockchain.unica.it/projects/ethereum-survey/attacks.html#simpledao
 * @author: -
 * @vulnerable_at_lines: 19
 */

pragma solidity ^0.4.2;

contract SimpleDAO {
  mapping (address => uint) public credit;

  function donate(address to) payable {
    credit[to] += msg.value;
  }

  function withdraw(uint amount) {
    if (credit[msg.sender]>= amount) {
      // <yes> <report> REENTRANCY
      bool res = msg.sender.call.value(amount)();
      credit[msg.sender]-=amount;
    }
  }

  function queryCredit(address to) returns (uint){
    return credit[to];
  }
}
