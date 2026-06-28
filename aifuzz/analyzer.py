"""Analysis orchestrator — the heart of `aifuzz analyze`.

Pipeline: ingest contract -> fuzz with Echidna (random or AI-guided) -> collect
findings -> Report. Fuzzing only; no static analysis.

When `auto=True` and the contract has no echidna_* oracle of its own, the
Tier-2 synthesizer (aifuzz.synthesize) tries to generate a harness from the
contract's structure (template-based, no AI). If the shape isn't recognised it
raises honestly — automatic harness generation for arbitrary contracts is M3.

Status: random fuzzing wired (M2); Tier-2 synthesis (M2.5); AI-guided = M3.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from . import __version__
from .fuzzer import EchidnaFuzzer
from .report import Report

# Funding config for synthesized reentrancy harnesses (the attacker needs ETH to
# seed the pool and stake). Mirrors harnesses/reentrancy.yaml.
_SYNTH_CONFIG = "balanceContract: 10000000000000000000\ntestLimit: 100000\n"


def analyze(contract_path: str, mode: str = "random", contract: str | None = None,
            config: str | None = None, auto: bool = False) -> Report:
    """Analyze a single contract and return a Report.

    Args:
        contract_path: path to a .sol file (a harness, or — with auto=True — a
            raw contract to synthesize a harness for).
        mode: "random" (baseline) or "ai-guided" (M3).
        contract: optional name of the test contract; passed to Echidna.
        config: optional Echidna YAML config path.
        auto: if True and the contract carries no echidna_* oracle, synthesize a
            harness from its structure (Tier-2 templates) and fuzz that.
    """
    path = Path(contract_path)
    if not path.exists():
        raise FileNotFoundError(f"contract not found: {contract_path}")

    report = Report(contract=path.name, mode=mode, tool_version=__version__)
    fuzzer = EchidnaFuzzer(mode=mode)

    src = path.read_text(encoding="utf-8", errors="replace")
    if auto and "echidna_" not in src:
        report.findings += _fuzz_synthesized(src, path.name, fuzzer)
    else:
        report.findings += fuzzer.fuzz(str(path), contract=contract, config=config)
    report.coverage = fuzzer.coverage
    report.elapsed = fuzzer.elapsed
    return report


def _fuzz_synthesized(src: str, target_name: str, fuzzer: EchidnaFuzzer):
    """Synthesize a harness for EACH vuln shape the contract matches, fuzz each in
    its own temp workdir, and aggregate the findings — so one contract can be
    reported for several vuln types. Raises honestly when no harness can be built
    (oracle-recognition or unknown shape)."""
    from .synthesize import synthesize_all, synthesize_harness

    builds = synthesize_all(src, "./" + target_name)
    if not builds:
        # No buildable shape: reuse the dispatcher's honest message (oracle / M3).
        raise RuntimeError(synthesize_harness(src, "./" + target_name).note)
    findings = []
    for b in builds:
        with tempfile.TemporaryDirectory(prefix="aifuzz-synth-") as wd:
            wdp = Path(wd)
            (wdp / target_name).write_text(src, encoding="utf-8")      # pristine copy
            hpath = wdp / f"{b.harness_name}.sol"
            hpath.write_text(b.harness_src, encoding="utf-8")
            cfg = wdp / "config.yaml"
            cfg.write_text(_SYNTH_CONFIG, encoding="utf-8")
            findings += fuzzer.fuzz(str(hpath), contract=b.harness_name, config=str(cfg))
    return findings
