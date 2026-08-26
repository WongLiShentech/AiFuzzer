"""Findings model and report serialization.

This module is fully implemented (it is pure data + formatting, with no external
tool dependency) so the rest of the system has a stable contract to produce.
Engines return ``Finding`` objects; a ``Report`` serializes them to JSON,
Markdown (human report), or SARIF 2.1.0 (the industry-standard interchange
format consumed by dashboards and CI).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _render_md_table(rows: list[list[str]]) -> list[str]:
    """Render a Markdown table with every column padded to a fixed width, so it
    stays aligned when printed to a plain terminal (and is still valid Markdown).
    `rows[0]` is the header."""
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    out = []
    for n, row in enumerate(rows):
        out.append("| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(row)) + " |")
        if n == 0:  # header separator
            out.append("|-" + "-|-".join("-" * w for w in widths) + "-|")
    return out


class Severity(str, Enum):
    """Severity levels, ordered low->high. SARIF maps these to its `level`."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def sarif_level(self) -> str:
        return {
            Severity.INFO: "note",
            Severity.LOW: "note",
            Severity.MEDIUM: "warning",
            Severity.HIGH: "error",
            Severity.CRITICAL: "error",
        }[self]


@dataclass
class Finding:
    """A single vulnerability finding produced by an engine."""

    rule_id: str               # e.g. "reentrancy", "access-control"
    title: str
    severity: Severity
    description: str
    contract: str              # contract file path or name
    engine: str                # which engine found it (e.g. "echidna", "slither")
    line: int | None = None    # 1-based source line, if known
    sequence: list[str] = field(default_factory=list)  # tx sequence that triggered it

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Report:
    """The result of analyzing one contract."""

    contract: str
    mode: str                  # "random" | "ai-guided"
    findings: list[Finding] = field(default_factory=list)
    tool_version: str = ""
    coverage: int | None = None    # unique code points the fuzzer reached
    elapsed: float | None = None   # wall-clock seconds the FUZZING took (Echidna only)
    total_elapsed: float | None = None  # seconds for the whole analysis, harness synthesis and
    # the LLM stages included. Reporting only `elapsed` understated AI mode badly -- an AI run
    # showing "13.5s" had actually taken 31s, because embedding, retrieval and generation all
    # happen before Echidna starts and were invisible. Comparing modes on `elapsed` alone
    # therefore made the slower arm look faster.
    harness_src: str | None = None     # the actual attacker+oracle Solidity Echidna ran, when
    harness_name: str | None = None    # synthesized (not the user's own upload). Without this
    # the dashboard's "Test harness" panel had nothing to show but the uploaded contract itself --
    # a real bug found via a live demo, where an access-control finding's own attack code
    # (attack_val_N, force_fund, the ValAttacker sub-contract) was invisible to the viewer.
    cot: str = ""              # phase-1 reasoning trace, ai-seed-cot mode only. Shown rather
    # than summarised: the arm's whole claim is that planning changes the sequences, and that
    # is only checkable if the plan is visible next to them.
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # ---- serializers -------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "mode": self.mode,
            "tool_version": self.tool_version,
            "coverage": self.coverage,
            "elapsed": self.elapsed,
            "total_elapsed": self.total_elapsed,
            "harness_src": self.harness_src,
            "harness_name": self.harness_name,
            "cot": self.cot,
            "created_at": self.created_at,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        n = len(self.findings)
        verdict = (f"VULNERABLE ({n} finding{'s' if n != 1 else ''})"
                   if n else "NO VULNERABILITIES FOUND")
        lines = [
            f"# Vulnerability Report - `{self.contract}`",
            "",
            f"- **Verdict:** {verdict}",
            f"- **Mode:** {self.mode}",
            f"- **Generated:** {self.created_at}",
            f"- **Findings:** {n}",
        ]
        if self.coverage is not None:
            lines.append(f"- **Coverage:** {self.coverage} code points reached")
        if self.total_elapsed is not None:
            lines.append(f"- **Time:** {self.total_elapsed}s total"
                         + (f" (fuzzing {self.elapsed}s)" if self.elapsed is not None else ""))
        elif self.elapsed is not None:
            lines.append(f"- **Time:** {self.elapsed}s")
        lines.append("")
        if not self.findings:
            lines.append("No vulnerabilities found.")
            return "\n".join(lines)
        rows = [["Severity", "Rule", "Title", "Line", "Engine"]]
        for f in sorted(self.findings, key=lambda x: x.severity.value):
            rows.append([
                f.severity.value,
                f"`{f.rule_id}`",
                f.title,
                str(f.line) if f.line is not None else "-",
                f.engine,
            ])
        lines += _render_md_table(rows)
        return "\n".join(lines)

    def to_sarif(self) -> dict[str, Any]:
        """Minimal valid SARIF 2.1.0 document for one contract's findings."""
        rules: dict[str, dict[str, Any]] = {}
        results = []
        for f in self.findings:
            rules.setdefault(
                f.rule_id,
                {"id": f.rule_id, "name": f.title,
                 "shortDescription": {"text": f.title}},
            )
            results.append(
                {
                    "ruleId": f.rule_id,
                    "level": f.severity.sarif_level,
                    "message": {"text": f.description},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.contract},
                                **(
                                    {"region": {"startLine": f.line}}
                                    if f.line is not None
                                    else {}
                                ),
                            }
                        }
                    ],
                }
            )
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "aifuzz",
                            "version": self.tool_version or "0.1.0",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
