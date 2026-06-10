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


class Severity(str, Enum):
    """Severity levels, ordered low→high. SARIF maps these to its `level`."""

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
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # ---- serializers -------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "mode": self.mode,
            "tool_version": self.tool_version,
            "created_at": self.created_at,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        lines = [
            f"# Vulnerability Report — `{self.contract}`",
            "",
            f"- **Mode:** {self.mode}",
            f"- **Generated:** {self.created_at}",
            f"- **Findings:** {len(self.findings)}",
            "",
        ]
        if not self.findings:
            lines.append("No vulnerabilities found.")
            return "\n".join(lines)
        lines += ["| Severity | Rule | Title | Line | Engine |", "|---|---|---|---|---|"]
        for f in sorted(self.findings, key=lambda x: x.severity.value):
            lines.append(
                f"| {f.severity.value} | `{f.rule_id}` | {f.title} | "
                f"{f.line if f.line is not None else '-'} | {f.engine} |"
            )
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
