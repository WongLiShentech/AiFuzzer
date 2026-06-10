"""Tests for the Echidna output parser (no Echidna needed — uses real samples)."""

from aifuzz.fuzzer import EchidnaFuzzer
from aifuzz.report import Severity

# A trimmed but faithful sample of Echidna's text summary for a falsified property
# (captured from a real run on AccessControlHarness.sol).
FALSIFIED = """\
[2026-06-09 19:12:21.33] [status] tests: 1/1, fuzzing: 404/5000, cov: 275, corpus: 4
echidna_owner_is_deployer: failed!\U0001f4a5
  Call sequence:
    AccessControlEchidnaTest.setOwner(0x0)

Traces:
"""

PASSED = """\
echidna_owner_is_deployer: passed! \U0001f389
"""


def test_parse_falsified_yields_one_high_finding():
    findings = EchidnaFuzzer._parse(FALSIFIED, "AccessControlHarness.sol")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.HIGH
    assert f.rule_id == "invariant-violation"
    assert f.engine == "echidna"
    assert "echidna_owner_is_deployer" in f.title
    # the triggering call sequence is captured
    assert any("setOwner(0x0)" in step for step in f.sequence)
    assert f.contract == "AccessControlHarness.sol"


def test_parse_passed_yields_no_findings():
    assert EchidnaFuzzer._parse(PASSED, "AccessControlHarness.sol") == []


def test_parse_empty_output_is_safe():
    assert EchidnaFuzzer._parse("", "X.sol") == []
