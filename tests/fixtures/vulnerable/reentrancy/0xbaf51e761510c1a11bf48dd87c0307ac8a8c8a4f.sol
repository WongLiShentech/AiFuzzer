/*
 * DATASET_SOURCE: https://github.com/smartbugs/smartbugs-curated/blob/main/dataset/reentrancy/0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol
 * VULNERABILITY_TYPE: Reentrancy
 * EEA_ETHTRUST_V3_SECTION: Section 3.4 - External Interactions and Re-entrancy Attacks
 * GROUND_TRUTH_LABEL: 1
 * ACADEMIC_BASIS: Real deployed mainnet contract from the curated set, providing an authentic (non-synthetic) in-the-wild reentrancy positive sample.
 * ORIGINAL_LICENSE: Apache-2.0 (SmartBugs Curated)
 */
/*
 * @source: etherscan.io 
 * @author: -
 * @vulnerable_at_lines: 41
 */

pragma solidity ^0.4.19;

contract ETH_VAULT
{
    mapping (address => uint) public balances;
    
    uint public MinDeposit = 1 ether;
    
    Log TransferLog;
    
    function ETH_VAULT(address _log)
    public 
    {
        TransferLog = Log(_log);
    }
    
    function Deposit()
    public
    payable
    {
        if(msg.value > MinDeposit)
        {
            balances[msg.sender]+=msg.value;
            TransferLog.AddMessage(msg.sender,msg.value,"Deposit");
        }
    }
    
    function CashOut(uint _am)
    public
    payable
    {
        if(_am<=balances[msg.sender])
        {
            // <yes> <report> REENTRANCY
            if(msg.sender.call.value(_am)())
            {
                balances[msg.sender]-=_am;
                TransferLog.AddMessage(msg.sender,_am,"CashOut");
            }
        }
    }
    
    function() public payable{}    
    
}

contract Log 
{
   
    struct Message
    {
        address Sender;
        string  Data;
        uint Val;
        uint  Time;
    }
    
    Message[] public History;
    
    Message LastMsg;
    
    function AddMessage(address _adr,uint _val,string _data)
    public
    {
        LastMsg.Sender = _adr;
        LastMsg.Time = now;
        LastMsg.Val = _val;
        LastMsg.Data = _data;
        History.push(LastMsg);
    }
}