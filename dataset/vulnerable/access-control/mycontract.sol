/*
 * DATASET_SOURCE: https://github.com/SmartContractSecurity/SWC-registry/blob/master/entries/docs/SWC-115.md (sample "mycontract.sol"; originally test_cases/authorization_through_tx.origin/mycontract.sol)
 * VULNERABILITY_TYPE: Access Control (Authorization through tx.origin)
 * EEA_ETHTRUST_V3_SECTION: Section 5 - Access Control ([S] No tx.origin)
 * GROUND_TRUTH_LABEL: 1
 * ACADEMIC_BASIS: Consensys Diligence canonical tx.origin authorization example; authorizing on tx.origin permits phishing via an intermediary contract (SWC-115).
 * ORIGINAL_LICENSE: MIT (SWC Registry)
 */

/*
 * @source: https://consensys.github.io/smart-contract-best-practices/recommendations/#avoid-using-txorigin
 * @author: Consensys Diligence
 * Modified by Gerhard Wagner
 */

pragma solidity 0.4.24;

contract MyContract {

    address owner;

    function MyContract() public {
        owner = msg.sender;
    }

    function sendTo(address receiver, uint amount) public {
        require(tx.origin == owner);
        receiver.transfer(amount);
    }

}
