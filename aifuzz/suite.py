"""Fuzzing-case suite runner -- `aifuzz suite`.

A declarative manifest (``tests/harnesses/registry.yaml``) is the single source of
truth mapping each fuzzing case: which dataset contract is under test, which
harness wraps it (supplying the oracle + attacker), which Echidna config funds
it, and the ground-truth expectation. This runner executes every case and checks
the result against that expectation:

  * ``expect: vulnerable`` -- the tool must report at least one finding.
  * ``expect: clean``      -- the tool must report zero findings.

Only the `expect` column is declared by the human (the answer key, derived from
the dataset labels). The `Findings` count and `Result` are computed live by
actually running Echidna -- nothing about the result is hardcoded. The pass/fail
table is the precision-vs-recall evidence for the evaluation (M5).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .analyzer import analyze


@dataclass
class CaseResult:
    name: str
    vuln_type: str
    expect: str                  # "vulnerable" | "clean"
    findings: int                # COMPUTED live from Echidna, not declared
    passed: bool
    detail: list[str] = field(default_factory=list)  # the violated invariant(s)
    error: str | None = None
    coverage: int | None = None  # unique code points the fuzzer reached
    elapsed: float | None = None # wall-clock seconds for this case


def _expectation_met(expect: str, findings: int) -> bool:
    if expect == "vulnerable":
        return findings >= 1
    if expect == "clean":
        return findings == 0
    raise ValueError(
        f"unknown expect value: {expect!r} (use 'vulnerable' or 'clean')"
    )


def load_cases(registry_path: str) -> list[dict]:
    path = Path(registry_path)
    if not path.exists():
        raise FileNotFoundError(f"registry not found: {registry_path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cases = data.get("cases", [])
    if not cases:
        raise ValueError(f"no cases defined in {registry_path}")
    return cases


def run_suite(registry_path: str, mode: str = "random") -> list[CaseResult]:
    """Run every case in the registry, returning a CaseResult per case.

    One failing/erroring case does not abort the suite -- its error is captured
    so the rest still run and the table stays complete.
    """
    results: list[CaseResult] = []
    for case in load_cases(registry_path):
        name = case.get("name", "<unnamed>")
        vuln_type = case.get("vuln_type", "-")
        expect = case.get("expect", "vulnerable")
        try:
            report = analyze(
                case["harness"],
                mode=mode,
                contract=case.get("contract"),
                config=case.get("config"),
            )
            n = len(report.findings)
            detail = [f.title for f in report.findings]
            results.append(
                CaseResult(name, vuln_type, expect, n,
                           _expectation_met(expect, n), detail,
                           coverage=report.coverage, elapsed=report.elapsed)
            )
        except Exception as e:  # noqa: BLE001 -- keep the suite going
            results.append(
                CaseResult(name, vuln_type, expect, 0, False, error=str(e))
            )
    return results


def _render_table(rows: list[list[str]]) -> list[str]:
    """Pad every column to a fixed width so the table aligns in a plain terminal
    (it is still valid Markdown)."""
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    out = []
    for n, row in enumerate(rows):
        out.append("| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(row)) + " |")
        if n == 0:  # header separator
            out.append("|-" + "-|-".join("-" * w for w in widths) + "-|")
    return out


def format_table(results: list[CaseResult]) -> str:
    # Columns mirror the dashboard's Evaluation view: the fuzzer's own verdict
    # (vulnerable/clean) alongside the known ground truth, and whether they match.
    header = ["Case", "Type", "Ground truth", "Fuzzer verdict", "Match"]
    rows = [header]
    for r in results:
        match = "PASS" if r.passed else "FAIL"
        if r.error:
            match += f" ({r.error.splitlines()[0]})"
        fuzzer_verdict = f"{'vulnerable' if r.findings >= 1 else 'clean'} ({r.findings})"
        rows.append([r.name, r.vuln_type, r.expect, fuzzer_verdict, match])

    lines = ["Evaluation -- fuzzer verdict vs. ground truth", ""]
    lines += _render_table(rows)

    passed = sum(1 for r in results if r.passed)
    lines += ["", f"{passed}/{len(results)} correct verdicts.", ""]

    # Live evidence: the actual invariants Echidna falsified (empty for clean cases).
    lines.append("Findings (live from Echidna):")
    any_findings = False
    for r in results:
        for title in r.detail:
            lines.append(f"  - [{r.name}] {title}")
            any_findings = True
    if not any_findings:
        lines.append("  (none)")
    return "\n".join(lines)
