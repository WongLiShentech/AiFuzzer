// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// A SAFE contract — its invariant can never be broken. Used in demos to show the
// fuzzer correctly reports NO vulnerability: proof it's genuinely searching, not
// blindly flagging everything. Pair it with a vulnerable harness for contrast.

contract SafeCounterEchidnaTest {
    uint256 public count;

    // Capped: count can never exceed 100, no matter how it's called.
    function increment() public {
        if (count < 100) {
            count += 1;
        }
    }

    // INVARIANT: count must always stay within bound. This holds forever, so
    // Echidna fuzzes hard and finds nothing → aifuzz reports "no vulnerabilities".
    function echidna_count_within_bound() public view returns (bool) {
        return count <= 100;
    }
}
