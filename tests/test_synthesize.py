"""Tests for Tier-2 harness synthesis (detection only — no Echidna needed).

These assert that each detector recognises the right shape on the REAL dataset
contracts, that detectors don't cross-match, and that the dispatcher degrades
honestly (recognise-only for oracle, "needs M3" for an unknown shape).
"""

from pathlib import Path

from aifuzz.synthesize import (
    detect_access_control_shape,
    detect_oracle_shape,
    detect_ordering_shape,
    detect_reentrancy_shape,
    synthesize_harness,
)

ROOT = Path(__file__).resolve().parent.parent
DS = ROOT / "dataset"


def _read(rel: str) -> str:
    return (DS / rel).read_text(encoding="utf-8", errors="replace")


# --- reentrancy ----------------------------------------------------------- #
def test_reentrancy_detected_on_simple_dao():
    shape = detect_reentrancy_shape(_read("vulnerable/reentrancy/simple_dao.sol"))
    assert shape is not None
    assert shape["contract"] == "SimpleDAO"
    assert shape["deposit"] == "donate"
    assert shape["deposit_takes_address"] is True
    assert shape["withdraw"] == "withdraw"


def test_dispatcher_builds_reentrancy_harness():
    out = synthesize_harness(_read("vulnerable/reentrancy/simple_dao.sol"), "./simple_dao.sol")
    assert out.built
    assert out.vuln_type == "reentrancy"
    assert "echidna_no_reentrancy_theft" in out.harness_src


# A withdraw-everything contract: withdrawBalance() takes NO amount argument.
_WITHDRAW_ALL = """
pragma solidity ^0.4.15;
contract Reentrance {
    mapping (address => uint) userBalance;
    function addToBalance() payable { userBalance[msg.sender] += msg.value; }
    function withdrawBalance() {
        if (!(msg.sender.call.value(userBalance[msg.sender])())) { throw; }
        userBalance[msg.sender] = 0;
    }
}
"""


def test_reentrancy_parameterless_withdraw_is_called_without_args():
    shape = detect_reentrancy_shape(_WITHDRAW_ALL)
    assert shape is not None and shape["withdraw_takes_amount"] is False
    out = synthesize_harness(_WITHDRAW_ALL, "./Reentrance.sol")
    assert out.built
    # must NOT pass an argument to a no-arg withdraw (that was the compile-error bug)
    assert "withdrawBalance()" in out.harness_src
    assert "withdrawBalance(1 ether)" not in out.harness_src


# --- access control ------------------------------------------------------- #
# A scratch contract with a PUBLIC owner + unguarded setter (template scope).
_PUBLIC_OWNER = """
pragma solidity ^0.4.24;
contract Vault {
    address public owner;
    function Vault() public { owner = msg.sender; }
    function changeOwner(address n) public { owner = n; }   // unguarded
}
"""


def test_access_control_detected_on_public_owner():
    shape = detect_access_control_shape(_PUBLIC_OWNER)
    assert shape is not None
    assert shape["owner_var"] == "owner"
    assert shape["setters"][0]["name"] == "changeOwner"
    assert shape["setters"][0]["takes_address"] is True


def test_access_control_detects_private_owner_via_probe():
    # dataset Unprotected.sol has `address private owner` (no getter) but a GUARDED
    # twin changeOwner_fixed(address) — the template probes ownership through it.
    shape = detect_access_control_shape(_read("vulnerable/access-control/Unprotected.sol"))
    assert shape is not None
    assert shape["owner_public"] is False
    assert shape["probe"] == "changeOwner_fixed"
    assert any(s["name"] == "changeOwner" for s in shape["setters"])


def test_access_control_skips_unobservable_private_owner():
    # private owner with NO guarded twin to probe -> ownership unobservable -> M3.
    src = ("pragma solidity ^0.4.24; contract C { address private owner;"
           " function C() public { owner = msg.sender; }"
           " function setOwner(address n) public { owner = n; } }")
    assert detect_access_control_shape(src) is None


def test_dispatcher_builds_access_control_harness():
    out = synthesize_harness(_PUBLIC_OWNER, "./Vault.sol")
    assert out.built and out.vuln_type == "access-control"
    assert "echidna_owner_unchanged" in out.harness_src


# --- ordering / TOD ------------------------------------------------------- #
def test_ordering_detected_on_tod_minimal():
    shape = detect_ordering_shape(_read("vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol"))
    assert shape is not None
    assert shape["funder"] == "setReward"
    assert shape["claimer"] == "claimReward"
    assert "submission" in shape["claimer_params"]


def test_dispatcher_builds_ordering_harness():
    out = synthesize_harness(
        _read("vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol"),
        "./eth_tx_order_dependence_minimal.sol")
    assert out.built and out.vuln_type == "ordering-attacks"
    assert "echidna_reward_not_stolen" in out.harness_src


# --- detectors don't cross-match ------------------------------------------ #
def test_reentrancy_not_seen_as_ordering():
    # simple_dao has a balance ledger -> ordering must defer to reentrancy.
    assert detect_ordering_shape(_read("vulnerable/reentrancy/simple_dao.sol")) is None


def test_ordering_not_seen_as_reentrancy():
    # the TOD game has no balance ledger -> reentrancy must not fire.
    assert detect_reentrancy_shape(
        _read("vulnerable/ordering-attacks/eth_tx_order_dependence_minimal.sol")) is None


# --- oracle: recognise only ----------------------------------------------- #
_ORACLE_LIKE = """
pragma solidity ^0.8.0;
contract Lender {
    uint256 public price;
    function setPrice(uint256 p) public { price = p; }
    function borrow(uint256 a) public { require(a <= collateral * price); }
    uint256 collateral;
}
"""


def test_oracle_recognised_but_not_built():
    out = synthesize_harness(_ORACLE_LIKE, "./Lender.sol")
    assert out.vuln_type == "oracle-manipulation"
    assert not out.built                      # honest: recognise-only, no harness
    assert "M3" in out.note


# --- unknown shape: honest skip ------------------------------------------- #
def test_unknown_shape_needs_m3():
    counter = "pragma solidity ^0.8.0;\ncontract C { uint256 public n; function inc() public { n++; } }"
    out = synthesize_harness(counter, "./C.sol")
    assert not out.built and out.vuln_type is None
    assert "M3" in out.note
