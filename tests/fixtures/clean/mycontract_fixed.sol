/*
 * DATASET_SOURCE: https://github.com/SmartContractSecurity/SWC-registry/blob/master/entries/docs/SWC-115.md (sample "mycontract_fixed.sol"; originally test_cases/authorization_through_tx.origin/mycontract_fixed.sol)
 * VULNERABILITY_TYPE: none
 * EEA_ETHTRUST_V3_SECTION: Section 5 - Access Control ([S] No tx.origin) (remediated)
 * GROUND_TRUTH_LABEL: 0
 * ACADEMIC_BASIS: SWC-115 remediated contract using msg.sender for authorization instead of tx.origin; true-negative control for the tx.origin class.
 * ORIGINAL_LICENSE: MIT (SWC Registry)
 */

/*
 * @source: https://consensys.github.io/smart-contract-best-practices/recommendations/#avoid-using-txorigin
 * @author: Consensys Diligence
 * Modified by Gerhard Wagner
 */

pragma solidity 0.4.25;

contract MyContract {

    address owner;

    function MyContract() public {
        owner = msg.sender;
    }

    function sendTo(address receiver, uint amount) public {
      require(msg.sender == owner);
      receiver.transfer(amount);
    }

}
