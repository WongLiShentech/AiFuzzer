#!/usr/bin/env python3
"""Evaluation harness -- the random-vs-AI-guided experiment (deliverable #3).

This is the methodology behind the project's headline claim: AI-guided input
generation finds bugs and reaches coverage that traditional random fuzzing does
not. It runs the labeled fuzzing suite (harnesses/registry.yaml) under each mode
and scores the results against ground truth.

FAIRNESS is the whole point of a credible comparison, so the experiment holds
everything constant except the one variable under test (random vs AI-guided):

  * SAME contracts + harnesses + oracles (the registry),
  * SAME transaction budget for both modes (ECHIDNA_TEST_LIMIT),
  * MULTIPLE trials per mode -- fuzzing is stochastic, so we report mean +/-
    stdev across trials, never a single lucky run.

Metrics:
  * bugs found (true positives) and the confusion matrix vs ground truth,
  * Precision / Recall / F1 / FPR (clean contracts supply the true-negatives),
  * (pending) code coverage and time-to-first-bug -- need Echidna corpus parsing.

Status: the random baseline runs today. AI-guided mode is wired but reports
"pending (M3)" until aifuzz.ai_guidance lands -- then this same script produces
the comparison with no further changes. Results print to stdout and results/.
"""

from __future__ import annotations

import json
import statistics
from pathlib import Path

from aifuzz.analyzer import analyze
from aifuzz.config import settings
from aifuzz.suite import run_suite, load_cases

REPO = Path(__file__).resolve().parent
REGISTRY = REPO / "harnesses" / "registry.yaml"
RESULTS = REPO / "results"
TRIALS = 3  # repeat each mode N times; fuzzing is stochastic (override below)


def prf(tp: int, fp: int, fn: int, tn: int) -> dict[str, float]:
    """Precision / Recall / F1 / FPR from a confusion matrix (real math)."""
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": fpr}


def _confusion(results) -> tuple[int, int, int, int]:
    """Turn one suite run into (tp, fp, fn, tn) against each case's ground truth."""
    tp = fp = fn = tn = 0
    for r in results:
        found = r.findings >= 1
        if r.expect == "vulnerable":
            tp += found
            fn += not found
        else:  # clean
            fp += found
            tn += not found
    return tp, fp, fn, tn


def _mode_available(mode: str, registry: str) -> bool:
    """random is always available; probe whether the AI engine (M3) exists yet."""
    if mode == "random":
        return True
    sample = load_cases(registry)[0]
    try:
        analyze(sample["harness"], mode=mode,
                contract=sample.get("contract"), config=sample.get("config"))
        return True
    except (NotImplementedError, ImportError, ModuleNotFoundError):
        return False
    except Exception:
        return True  # a different error -- let the real run surface it


def run_mode(mode: str, registry: str, trials: int) -> dict | None:
    """Run `trials` suite passes for one mode; aggregate metrics mean +/- stdev.
    Returns None if the mode's engine is not implemented yet (e.g. AI = M3)."""
    if not _mode_available(mode, registry):
        return None
    per_trial = []
    for _ in range(trials):
        results = run_suite(registry, mode=mode)
        tp, fp, fn, tn = _confusion(results)
        m = prf(tp, fp, fn, tn)
        m["bugs_found"] = tp
        per_trial.append(m)

    agg = {}
    for key in ("bugs_found", "precision", "recall", "f1", "fpr"):
        vals = [t[key] for t in per_trial]
        agg[key] = {
            "mean": statistics.mean(vals),
            "stdev": statistics.stdev(vals) if len(vals) > 1 else 0.0,
        }
    agg["trials"] = trials
    return agg


def _fmt(stat: dict) -> str:
    return f"{stat['mean']:.2f} +/- {stat['stdev']:.2f}"


def main(trials: int = TRIALS) -> int:
    cases = load_cases(str(REGISTRY))
    vulnerable = sum(1 for c in cases if c.get("expect") == "vulnerable")
    clean = sum(1 for c in cases if c.get("expect") == "clean")

    print("Random vs AI-guided fuzzing -- evaluation")
    print(f"  cases:        {len(cases)} ({vulnerable} vulnerable, {clean} clean)")
    print(f"  budget/mode:  {settings.echidna_test_limit} tx (identical for both modes)")
    print(f"  trials/mode:  {trials} (stochastic -- mean +/- stdev reported)")
    print()

    report = {}
    rows = [["Metric", "Random (baseline)", "AI-guided"]]
    random_agg = run_mode("random", str(REGISTRY), trials)
    ai_agg = run_mode("ai-guided", str(REGISTRY), trials)
    report["random"] = random_agg
    report["ai_guided"] = ai_agg

    ai_cell = (lambda k: _fmt(ai_agg[k])) if ai_agg else (lambda k: "pending (M3)")
    for key, label in (("bugs_found", "Bugs found (TP)"), ("recall", "Recall"),
                       ("precision", "Precision"), ("f1", "F1"), ("fpr", "FPR")):
        rows.append([label, _fmt(random_agg[key]), ai_cell(key)])

    widths = [max(len(r[i]) for r in rows) for i in range(3)]
    for n, row in enumerate(rows):
        print("| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(row)) + " |")
        if n == 0:
            print("|-" + "-|-".join("-" * w for w in widths) + "-|")

    if ai_agg is None:
        print("\nAI-guided mode reports pending until aifuzz.ai_guidance (M3) is implemented.")
        print("Once it lands, re-run this script unchanged to get the full comparison.")

    RESULTS.mkdir(exist_ok=True)
    out = RESULTS / "benchmark.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nWrote {out.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    import sys
    n = int(sys.argv[1]) if len(sys.argv) > 1 else TRIALS
    raise SystemExit(main(n))
