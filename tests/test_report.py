"""Tests for the findings/report layer (the one fully-implemented module)."""

from aifuzz.report import Finding, Report, Severity


def _sample_report() -> Report:
    return Report(
        contract="EtherStore.sol",
        mode="random",
        tool_version="0.1.0",
        findings=[
            Finding(
                rule_id="reentrancy",
                title="Reentrancy in withdraw()",
                severity=Severity.HIGH,
                description="External call before state update allows re-entry.",
                contract="EtherStore.sol",
                engine="echidna",
                line=42,
                sequence=["deposit()", "withdraw()", "withdraw()"],
            )
        ],
    )


def test_severity_sarif_mapping():
    assert Severity.HIGH.sarif_level == "error"
    assert Severity.MEDIUM.sarif_level == "warning"
    assert Severity.INFO.sarif_level == "note"


def test_finding_to_dict_serializes_enum():
    f = _sample_report().findings[0]
    d = f.to_dict()
    assert d["severity"] == "high"
    assert d["rule_id"] == "reentrancy"
    assert d["line"] == 42


def test_report_json_roundtrip():
    import json

    data = json.loads(_sample_report().to_json())
    assert data["contract"] == "EtherStore.sol"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["severity"] == "high"


def test_report_markdown_contains_finding():
    md = _sample_report().to_markdown()
    assert "Vulnerability Report" in md
    assert "reentrancy" in md


def test_report_empty_markdown():
    md = Report(contract="Safe.sol", mode="random").to_markdown()
    assert "No vulnerabilities found." in md


def test_sarif_is_valid_shape():
    sarif = _sample_report().to_sarif()
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "aifuzz"
    assert run["results"][0]["ruleId"] == "reentrancy"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 42
