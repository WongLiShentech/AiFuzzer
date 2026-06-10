"""Echidna fuzzing engine — the core analysis engine.

Runs Echidna against a contract in one of two modes:
  * "random"     — stock coverage-guided random fuzzing (the baseline).
  * "ai-guided"  — properties + seed sequences from aifuzz.ai_guidance (the experiment).

The headline result of the project is the comparison between these two modes
(coverage reached, vulnerabilities found). Echidna runs inside the Linux
container (see Dockerfile) so it works regardless of host OS.

Status: random mode implemented (M2). AI-guided mode = M3.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile

from .config import settings
from .report import Finding, Severity

# Echidna's end-of-run summary prints one line per property, e.g.:
#   echidna_owner_is_deployer: failed!💥
# followed by an indented "Call sequence:" block. We parse that (the text output
# is far richer than --format json, which omits the real name and arguments).
_RESULT_RE = re.compile(r"^(\w+):\s*(passed|failed)!")


class EchidnaFuzzer:
    def __init__(self, mode: str = "random") -> None:
        if mode not in ("random", "ai-guided"):
            raise ValueError(f"unknown mode: {mode!r}")
        self.mode = mode
        self.test_limit = settings.echidna_test_limit  # configurable, not hardcoded

    def fuzz(self, contract_path: str, contract: str | None = None) -> list[Finding]:
        """Fuzz the contract and return any property violations as Findings.

        Args:
            contract_path: path to the .sol file containing the Echidna harness.
            contract: optional name of the test contract (the one with the
                echidna_* properties). If omitted, Echidna auto-selects.
        """
        if self.mode == "ai-guided":
            # M3: the AI layer proposes properties + seed sequences, then we fuzz.
            from .ai_guidance import PropertyGenerator  # noqa: F401
            raise NotImplementedError("TODO(M3): AI-guided Echidna run")
        return self._run_random(contract_path, contract)

    def _run_random(self, contract_path: str, contract: str | None) -> list[Finding]:
        if shutil.which("echidna") is None:
            raise RuntimeError(
                "echidna not found on PATH. The fuzzer runs inside the Linux "
                "Docker image — use `docker compose run --rm --no-deps aifuzz "
                "python -m aifuzz.cli analyze <contract>` (see README)."
            )
        # Use an absolute path so we can run Echidna from a throwaway working
        # directory. Echidna/crytic-compile drop a `crytic-export/` folder in the
        # CWD; running from a temp dir keeps that scratch out of the user's repo.
        abs_path = os.path.abspath(contract_path)
        cmd = ["echidna", abs_path, "--test-limit", str(self.test_limit)]
        if contract:
            cmd += ["--contract", contract]
        with tempfile.TemporaryDirectory(prefix="aifuzz-") as workdir:
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=workdir)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return self._parse(output, contract_path)

    @staticmethod
    def _parse(output: str, contract_path: str) -> list[Finding]:
        """Turn Echidna's text summary into Findings (one per falsified property)."""
        findings: list[Finding] = []
        lines = output.splitlines()
        for i, raw in enumerate(lines):
            m = _RESULT_RE.match(raw.strip())
            if not m or m.group(2) != "failed":
                continue
            name = m.group(1)
            sequence = _collect_call_sequence(lines, i + 1)
            findings.append(
                Finding(
                    rule_id="invariant-violation",
                    title=f"Invariant `{name}` violated by fuzzing",
                    severity=Severity.HIGH,
                    description=(
                        f"Echidna falsified the property `{name}`. A generated "
                        f"transaction sequence drove the contract into a state "
                        f"that breaks the invariant:\n"
                        + ("\n".join(f"  {c}" for c in sequence) or "  (sequence unavailable)")
                    ),
                    contract=os.path.basename(contract_path),
                    engine="echidna",
                    sequence=sequence,
                )
            )
        return findings


def _collect_call_sequence(lines: list[str], start: int) -> list[str]:
    """Read the indented call-sequence block after a falsified property."""
    seq: list[str] = []
    for j in range(start, len(lines)):
        s = lines[j].strip()
        if s.startswith("Call sequence:"):
            continue
        # stop at a blank line, the traces section, or the next property result
        if not s or s.startswith("Traces") or _RESULT_RE.match(s):
            break
        seq.append(s)
    return seq
