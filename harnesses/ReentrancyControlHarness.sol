pragma solidity 0.4.24;

// REENTRANCY true-negative control (Mechanism A) wrapping the REAL fixed dataset
// contract: dataset/clean/simple_dao_fixed.sol — the SAME SimpleDAO as the
// vulnerable one, but remediated with checks-effects-interactions (it debits
// credit BEFORE sending ETH).
//
// This is the identical attacker + oracle as ReentrancyHarness.sol, only the
// imported target differs. Running it proves the tool does NOT cry wolf: against
// patched code the reentrancy oracle HOLDS, so Echidna reports 0 findings. The
// vulnerable/fixed pair is the true-positive / true-negative evidence the
// evaluation (precision vs recall) is built on.
import "../dataset/clean/simple_dao_fixed.sol";

contract ReentrancyControlEchidnaTest {
    SimpleDAO public dao;
    uint256 public donatedSelf;   // ETH we put into the pool crediting OURSELVES
    uint256 public received;      // ETH the pool has paid back to us
    bool internal attacking;

    // Payable so Echidna can fund it (balanceContract config gives it ETH).
    function ReentrancyControlEchidnaTest() public payable {
        dao = new SimpleDAO();
    }

    // Seed the pool: a victim deposits 2 ETH, the attacker deposits 1 ETH.
    function setup() public {
        if (donatedSelf == 0 && address(this).balance >= 3 ether) {
            dao.donate.value(2 ether)(address(0xdead)); // victim's money in the pool
            dao.donate.value(1 ether)(this);            // attacker's own money
            donatedSelf = 1 ether;
        }
    }

    // Trigger the withdrawal that WOULD re-enter on the vulnerable contract.
    function attack() public {
        if (donatedSelf > 0) {
            attacking = true;
            dao.withdraw(1 ether);
            attacking = false;
        }
    }

    // Re-entry hook: on the FIXED contract our credit is already zeroed before
    // this fires, so the inner withdraw pays nothing — the oracle stays true.
    function () public payable {
        received += msg.value;
        if (attacking && address(dao).balance >= 1 ether) {
            dao.withdraw(1 ether);
        }
    }

    // SAME REENTRANCY ORACLE as the vulnerable harness. Against patched code it
    // must HOLD (received never exceeds donatedSelf) → 0 findings → no false alarm.
    function echidna_no_reentrancy_theft() public view returns (bool) {
        return received <= donatedSelf;
    }
}
