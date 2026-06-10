"""Analysis orchestrator — the heart of `aifuzz analyze`.

Pipeline: ingest contract → fuzz with Echidna (random or AI-guided) → collect
findings → Report. Fuzzing only; no static analysis.

Status: random fuzzing wired (M2); AI-guided mode = M3.
"""

from __future__ import annotations

from pathlib import Path

from . import __version__
from .fuzzer import EchidnaFuzzer
from .report import Report


def analyze(contract_path: str, mode: str = "random", contract: str | None = None) -> Report:
    """Analyze a single contract and return a Report.

    Args:
        contract_path: path to a .sol file (containing the Echidna harness).
        mode: "random" (baseline) or "ai-guided" (the experiment).
        contract: optional name of the test contract (the one with the
            echidna_* properties); passed through to Echidna.
    """
    path = Path(contract_path)
    if not path.exists():
        raise FileNotFoundError(f"contract not found: {contract_path}")

    report = Report(contract=path.name, mode=mode, tool_version=__version__)
    fuzzer = EchidnaFuzzer(mode=mode)
    report.findings += fuzzer.fuzz(str(path), contract=contract)
    return report
