/*
 * DATASET_SOURCE: https://github.com/smartbugs/smartbugs-curated/blob/main/dataset/front_running/eth_tx_order_dependence_minimal.sol
 * VULNERABILITY_TYPE: Ordering Attacks (Front-Running)
 * EEA_ETHTRUST_V3_SECTION: Section 3.8 - Transaction Ordering Dependence / Front-Running
 * GROUND_TRUTH_LABEL: 1
 * ACADEMIC_BASIS: Minimal reward-claim contract whose payout depends on transaction ordering, isolating transaction-order dependence.
 * ORIGINAL_LICENSE: Apache-2.0 (SmartBugs Curated)
 */
/*
 * @source: https://github.com/ConsenSys/evm-analyzer-benchmark-suite
 * @author: Suhabe Bugrara
 * @vulnerable_at_lines: 23,31
 */

pragma solidity ^0.4.16;

contract EthTxOrderDependenceMinimal {
    address public owner;
    bool public claimed;
    uint public reward;

    function EthTxOrderDependenceMinimal() public {
        owner = msg.sender;
    }

    function setReward() public payable {
        require (!claimed);

        require(msg.sender == owner);
        // <yes> <report> FRONT_RUNNING
        owner.transfer(reward);
        reward = msg.value;
    }

    function claimReward(uint256 submission) {
        require (!claimed);
        require(submission < 10);
        // <yes> <report> FRONT_RUNNING
        msg.sender.transfer(reward);
        claimed = true;
    }
}
