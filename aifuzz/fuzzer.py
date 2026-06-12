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

# Echidna prints one line per property in its summary. The wording varies:
#   echidna_owner_is_deployer: failed!           (a violation, with a Call sequence)
#   echidna_no_reentrancy_theft: failed with no transactions made 
#   echidna_count_within_bound: passing            (held — present tense when ALL pass)
#   echidna_x: passed!                             (held — past tense in other runs)
# We match pass*/fail* so a clean contract ("passing") is recognised as a real
# result, not mistaken for "no properties evaluated".
_RESULT_RE = re.compile(r"^(\w+):\s*(pass(?:ed|ing)|fail(?:ed|ing))\b")
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")


def _solc_for_pragma(contract_path: str) -> str | None:
    """Pick an installed solc matching the file's pragma. solc-select honours the
    SOLC_VERSION env var per run, so old dataset contracts compile without
    changing the global default; the fuzzer self-heals (installs) a missing one.

    Handles the legacy 0.4.x line two ways:
      * an exact pin (`pragma solidity 0.4.24;`) -> that precise version, because
        a non-range pragma rejects any other compiler;
      * a caret/range (`^0.4.2`, `>=0.4.0 <0.5.0`) -> the newest 0.4 we ship.
    A 0.8.x (or anything else) pragma falls through to the image default."""
    try:
        text = open(contract_path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    m = _PRAGMA_RE.search(text)
    if not m:
        return None
    spec = m.group(1).strip()
    if "0.4" not in spec:
        return None  # default to the image's solc (0.8.x)
    if re.fullmatch(r"0\.4\.\d+", spec):
        return spec  # exact pin, e.g. "0.4.24" — must use exactly this
    return "0.4.26"  # caret/range on 0.4.x -> newest installed 0.4


class EchidnaFuzzer:
    def __init__(self, mode: str = "random") -> None:
        if mode not in ("random", "ai-guided"):
            raise ValueError(f"unknown mode: {mode!r}")
        self.mode = mode
        self.test_limit = settings.echidna_test_limit  # configurable, not hardcoded

    def fuzz(self, contract_path: str, contract: str | None = None,
             config: str | None = None) -> list[Finding]:
        """Fuzz the contract and return any property violations as Findings.

        Args:
            contract_path: path to the .sol file containing the Echidna harness.
            contract: optional name of the test contract (the one with the
                echidna_* properties). If omitted, Echidna auto-selects.
            config: optional path to an Echidna YAML config (e.g. to fund the
                harness via `balanceContract`).
        """
        if self.mode == "ai-guided":
            # M3: the AI layer proposes properties + seed sequences, then we fuzz.
            from .ai_guidance import PropertyGenerator  # noqa: F401
            raise NotImplementedError("TODO(M3): AI-guided Echidna run")
        return self._run_random(contract_path, contract, config)

    def _run_random(self, contract_path: str, contract: str | None,
                    config: str | None = None) -> list[Finding]:
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
        if config:
            cmd += ["--config", os.path.abspath(config)]
        env = dict(os.environ)
        solc = _solc_for_pragma(contract_path)
        if solc:
            env["SOLC_VERSION"] = solc  # solc-select honours this per run
            # ensure that compiler is available (idempotent; downloads only if missing)
            subprocess.run(["solc-select", "install", solc],
                           capture_output=True, text=True, env=env)
        with tempfile.TemporaryDirectory(prefix="aifuzz-") as workdir:
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=workdir, env=env)
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        # Honesty guard: only trust an "all clear" if Echidna actually evaluated a
        # property. No result lines => compile error / no echidna_* props => surface it
        # rather than silently reporting "no vulnerabilities found".
        if not any(_RESULT_RE.match(line.strip()) for line in output.splitlines()):
            tail = "\n".join(output.strip().splitlines()[-12:])
            raise RuntimeError(
                "Echidna evaluated no properties (likely a compile error or no "
                "echidna_* functions in the contract). Echidna output:\n" + tail
            )
        return self._parse(output, contract_path)

    @staticmethod
    def _parse(output: str, contract_path: str) -> list[Finding]:
        """Turn Echidna's text summary into Findings (one per falsified property)."""
        findings: list[Finding] = []
        lines = output.splitlines()
        for i, raw in enumerate(lines):
            m = _RESULT_RE.match(raw.strip())
            if not m or not m.group(2).startswith("fail"):
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
