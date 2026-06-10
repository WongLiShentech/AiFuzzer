/*
 * DATASET_SOURCE: https://github.com/smartbugs/smartbugs-curated/blob/main/dataset/front_running/FindThisHash.sol
 * VULNERABILITY_TYPE: Ordering Attacks (Front-Running)
 * EEA_ETHTRUST_V3_SECTION: Section 3.8 - Transaction Ordering Dependence / Front-Running
 * GROUND_TRUTH_LABEL: 1
 * ACADEMIC_BASIS: Hash-puzzle reward contract vulnerable to front-running of the winning-solution submission.
 * ORIGINAL_LICENSE: Apache-2.0 (SmartBugs Curated)
 */
/*
 * @source: https://github.com/sigp/solidity-security-blog
 * @author: -
 * @vulnerable_at_lines: 17
 */

pragma solidity ^0.4.22;

contract FindThisHash {
    bytes32 constant public hash = 0xb5b5b97fafd9855eec9b41f74dfb6c38f5951141f9a3ecd7f44d5479b630ee0a;

    constructor() public payable {} // load with ether

    function solve(string solution) public {
        // If you can find the pre image of the hash, receive 1000 ether
         // <yes> <report> FRONT_RUNNING
        require(hash == sha3(solution));
        msg.sender.transfer(1000 ether);
    }
}
