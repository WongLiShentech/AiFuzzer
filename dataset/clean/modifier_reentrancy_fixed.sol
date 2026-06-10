/*
 * DATASET_SOURCE: https://github.com/SmartContractSecurity/SWC-registry/blob/master/entries/docs/SWC-107.md (sample "modifier_reentrancy_fixed.sol"; originally test_cases/reentrancy/modifier_reentrancy_fixed.sol)
 * VULNERABILITY_TYPE: none
 * EEA_ETHTRUST_V3_SECTION: Section 3.4 - External Interactions and Re-entrancy Attacks (remediated)
 * GROUND_TRUTH_LABEL: 0
 * ACADEMIC_BASIS: SWC-107 remediated modifier-ordering contract (supportsToken before hasNoBalance); true-negative control for modifier-based reentrancy.
 * ORIGINAL_LICENSE: MIT (SWC Registry)
 */

pragma solidity ^0.5.0;

contract ModifierEntrancy {
  mapping (address => uint) public tokenBalance;
  string constant name = "Nu Token";
  Bank bank;
  constructor() public{
      bank = new Bank();
  }

  //If a contract has a zero balance and supports the token give them some token
  function airDrop() supportsToken hasNoBalance  public{ // In the fixed version supportsToken comes before hasNoBalance
    tokenBalance[msg.sender] += 20;
  }

  //Checks that the contract responds the way we want
  modifier supportsToken() {
    require(keccak256(abi.encodePacked("Nu Token")) == bank.supportsToken());
    _;
  }
  //Checks that the caller has a zero balance
  modifier hasNoBalance {
      require(tokenBalance[msg.sender] == 0);
      _;
  }
}

contract Bank{

    function supportsToken() external returns(bytes32){
        return(keccak256(abi.encodePacked("Nu Token")));
    }
}
