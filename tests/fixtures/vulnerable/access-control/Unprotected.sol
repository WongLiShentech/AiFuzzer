/*
 * DATASET_SOURCE: https://github.com/crytic/not-so-smart-contracts/blob/master/unprotected_function/Unprotected.sol
 * VULNERABILITY_TYPE: Access Control
 * EEA_ETHTRUST_V3_SECTION: Section 5 - Access Control
 * GROUND_TRUTH_LABEL: 1
 * ACADEMIC_BASIS: Minimal Trail of Bits example of a state-changing function missing an access-control modifier, isolating the unprotected-function pattern.
 * ORIGINAL_LICENSE: Apache-2.0 (Trail of Bits, not-so-smart-contracts)
 */
pragma solidity ^0.4.15;

contract Unprotected{
    address private owner;

    modifier onlyowner {
        require(msg.sender==owner);
        _;
    }

    function Unprotected()
        public 
    {
        owner = msg.sender;
    }

    // This function should be protected
    function changeOwner(address _newOwner) 
        public
    {
       owner = _newOwner;
    }

    function changeOwner_fixed(address _newOwner) 
        public 
        onlyowner
    {
       owner = _newOwner;
    }
}
