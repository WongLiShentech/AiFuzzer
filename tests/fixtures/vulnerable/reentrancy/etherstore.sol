/*
 * DATASET_SOURCE: https://github.com/smartbugs/smartbugs-curated/blob/main/dataset/reentrancy/etherstore.sol
 * VULNERABILITY_TYPE: Reentrancy
 * EEA_ETHTRUST_V3_SECTION: Section 3.4 - External Interactions and Re-entrancy Attacks
 * GROUND_TRUTH_LABEL: 1
 * ACADEMIC_BASIS: Widely cited EtherStore teaching contract demonstrating withdraw-pattern reentrancy with state updated after the external call.
 * ORIGINAL_LICENSE: Apache-2.0 (SmartBugs Curated)
 */
/*
 * @source: https://github.com/sigp/solidity-security-blog
 * @author: Suhabe Bugrara
 * @vulnerable_at_lines: 27
 */

//added pragma version
pragma solidity ^0.4.10;

contract EtherStore {

    uint256 public withdrawalLimit = 1 ether;
    mapping(address => uint256) public lastWithdrawTime;
    mapping(address => uint256) public balances;

    function depositFunds() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds (uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        // limit the withdrawal
        require(_weiToWithdraw <= withdrawalLimit);
        // limit the time allowed to withdraw
        require(now >= lastWithdrawTime[msg.sender] + 1 weeks);
        // <yes> <report> REENTRANCY
        require(msg.sender.call.value(_weiToWithdraw)());
        balances[msg.sender] -= _weiToWithdraw;
        lastWithdrawTime[msg.sender] = now;
    }
 }
