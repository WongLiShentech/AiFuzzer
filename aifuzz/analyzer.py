"""Analysis orchestrator — the heart of `aifuzz analyze`.

Pipeline: ingest contract -> fuzz with Echidna (random or AI-guided) -> collect
findings -> Report. Fuzzing only; no static analysis.

When `auto=True` and the contract has no echidna_* oracle of its own, the
Tier-2 synthesizer (aifuzz.synthesize) tries to generate a harness from the
contract's structure (template-based, no AI). If the shape isn't recognised it
raises honestly rather than guessing at a shape it cannot model.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from . import __version__
from .fuzzer import EchidnaFuzzer
from .report import Report

# Funding config for synthesized reentrancy harnesses (the attacker needs ETH to
# seed the pool and stake). Mirrors tests/harnesses/reentrancy.yaml.
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
    _t0 = time.monotonic()   # whole analysis, so AI's LLM stages are visible in the timing

    src = path.read_text(encoding="utf-8", errors="replace")
    if mode == "ai-guided":
        report.findings += _fuzz_ai_guided(src, path.name, fuzzer, report)
    elif mode in ("ai-seed", "ai-seed-cot"):
        report.findings += _fuzz_ai_seeded(src, path.name, fuzzer, report,
                                           cot=(mode == "ai-seed-cot"))
    elif auto and "echidna_" not in src:
        report.findings += _fuzz_synthesized(src, path.name, fuzzer, report)
    else:
        # The uploaded file IS the harness here (it carries its own echidna_ oracle already),
        # so it's accurate -- not a placeholder -- for the dashboard to show it as such.
        report.harness_src, report.harness_name = src, path.stem
        report.findings += fuzzer.fuzz(str(path), contract=contract, config=config)
    report.coverage = fuzzer.coverage
    report.elapsed = fuzzer.elapsed
    report.total_elapsed = round(time.monotonic() - _t0, 2)
    return report


def _fuzz_ai_guided(src: str, target_name: str, fuzzer: EchidnaFuzzer, report: Report):
    """AI-guided run (M3). Both LLM stages are RAG-grounded: the contract is embedded and
    similar contracts are retrieved from the reference corpus, then

      1. Qwen writes the harness (attacker + echidna_ invariants), behind a
         compile-check -> feed-the-error-back -> retry loop, and
      2. Qwen proposes transaction sequences, which seed Echidna's corpus.

    Stage 2 degrades to plain random search if the model returns nothing usable; stage 1
    cannot, so a model that never produces a compiling harness raises rather than silently
    falling back to the template arm -- otherwise the AI mode would quietly BE the manual mode."""
    from .ai_guidance import PropertyGenerator
    try:
        pg = PropertyGenerator()
    except Exception as e:
        raise RuntimeError(f"AI backend unavailable (Ollama/ChromaDB): {e}") from e

    res = pg.generate_harness(src, "./" + target_name)
    if not res:
        raise RuntimeError(
            "AI-guided analysis failed: the model could not produce a compiling harness "
            "within its retry budget. This is reported rather than masked -- falling back to "
            "the template harness would make the AI mode indistinguishable from manual mode.")
    harness_src, harness_name, _attempts = res
    report.harness_src, report.harness_name = harness_src, harness_name

    seeds = []
    try:
        from .synthesize import coverage_forwarder_specs
        spec = coverage_forwarder_specs(src)
        if spec:
            seeds = pg.seed_sequences(src, spec[1])
    except Exception:
        seeds = []

    with tempfile.TemporaryDirectory(prefix="aifuzz-ai-") as wd:
        wdp = Path(wd)
        (wdp / target_name).write_text(src, encoding="utf-8")
        hpath = wdp / f"{harness_name}.sol"
        hpath.write_text(harness_src, encoding="utf-8")
        cfg = wdp / "config.yaml"
        cfg.write_text(_SYNTH_CONFIG, encoding="utf-8")
        return fuzzer.fuzz(str(hpath), contract=harness_name, config=str(cfg), seeds=seeds or None)


def _fuzz_ai_seeded(src: str, target_name: str, fuzzer: EchidnaFuzzer, report: Report,
                    cot: bool = False):
    """B1: AI-GUIDED INPUTS ONLY -- the project's actual research question. The harness is the
    SAME deterministic coverage-forwarding template as random mode (identical code path to
    _fuzz_synthesized's coverage branch); the only difference is that Echidna's corpus is
    pre-seeded with RAG-grounded LLM-proposed transaction sequences before fuzzing starts. This
    isolates input generation as the sole variable, unlike ai-guided (M3) which also lets the
    model author the harness. A seeding failure degrades to plain random fuzzing (empty seeds),
    never to an error -- the harness never depended on the AI succeeding."""
    from .synthesize import synthesize_coverage_harness, coverage_forwarder_specs

    cov = synthesize_coverage_harness(src, "./" + target_name)
    if not cov:
        raise RuntimeError(
            "Could not synthesize a coverage harness for this contract -- automatic harness "
            "generation for arbitrary contracts is limited to recognised ABI shapes.")
    harness_src, harness_name = cov
    report.harness_src, report.harness_name = harness_src, harness_name

    seeds = []
    try:
        from .ai_guidance import PropertyGenerator
        pg = PropertyGenerator()
        spec = coverage_forwarder_specs(src)
        if spec:
            seeds = (pg.seed_sequences_cot(src, spec[1]) if cot
                     else pg.seed_sequences(src, spec[1]))
            report.cot = pg.last_cot if cot else ""
    except Exception:
        seeds = []  # honest degrade to random -- never blocks the fuzz run

    with tempfile.TemporaryDirectory(prefix="aifuzz-seed-") as wd:
        wdp = Path(wd)
        (wdp / target_name).write_text(src, encoding="utf-8")
        hpath = wdp / f"{harness_name}.sol"
        hpath.write_text(harness_src, encoding="utf-8")
        cfg = wdp / "config.yaml"
        cfg.write_text(_SYNTH_CONFIG, encoding="utf-8")
        return fuzzer.fuzz(str(hpath), contract=harness_name, config=str(cfg), seeds=seeds or None)


def _fuzz_synthesized(src: str, target_name: str, fuzzer: EchidnaFuzzer, report: Report):
    """Synthesize a harness for EACH vuln shape the contract matches, fuzz each in
    its own temp workdir, and aggregate the findings — so one contract can be
    reported for several vuln types. Raises honestly when no harness can be built
    (oracle-recognition or unknown shape)."""
    from .synthesize import synthesize_all, synthesize_harness, synthesize_coverage_harness

    # Prefer the generic ABI-forwarding harness -- the one the evaluation actually measures
    # (66.5% mean coverage, and it carries the theft / selfdestruct / solvency oracles). The
    # older per-shape templates only fire when a contract matches a known shape, so relying on
    # them alone made the dashboard reject contracts the benchmarked tool handles fine.
    cov = synthesize_coverage_harness(src, "./" + target_name)
    if cov:
        harness_src, harness_name = cov
        report.harness_src, report.harness_name = harness_src, harness_name
        with tempfile.TemporaryDirectory(prefix="aifuzz-cov-") as wd:
            wdp = Path(wd)
            (wdp / target_name).write_text(src, encoding="utf-8")
            hpath = wdp / f"{harness_name}.sol"
            hpath.write_text(harness_src, encoding="utf-8")
            cfg = wdp / "config.yaml"
            cfg.write_text(_SYNTH_CONFIG, encoding="utf-8")
            return fuzzer.fuzz(str(hpath), contract=harness_name, config=str(cfg))

    builds = synthesize_all(src, "./" + target_name)
    if not builds:
        # No buildable shape: reuse the dispatcher's honest message (oracle / M3).
        raise RuntimeError(synthesize_harness(src, "./" + target_name).note)
    findings = []
    for b in builds:
        if report.harness_src is None:   # show the first -- multiple builds can't fit one field
            report.harness_src, report.harness_name = b.harness_src, b.harness_name
        with tempfile.TemporaryDirectory(prefix="aifuzz-synth-") as wd:
            wdp = Path(wd)
            (wdp / target_name).write_text(src, encoding="utf-8")      # pristine copy
            hpath = wdp / f"{b.harness_name}.sol"
            hpath.write_text(b.harness_src, encoding="utf-8")
            cfg = wdp / "config.yaml"
            cfg.write_text(_SYNTH_CONFIG, encoding="utf-8")
            findings += fuzzer.fuzz(str(hpath), contract=b.harness_name, config=str(cfg))
    return findings
