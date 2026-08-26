#!/usr/bin/env python3
"""Why this evaluation reports precision / recall / F1 rather than accuracy.

The argument is empirical, not stylistic: the test set is heavily imbalanced (39 vulnerable
contracts against 639 clean ones), and under that imbalance accuracy rewards a detector that
finds nothing at all. This script derives that from the real results file, so the metric
choice can be defended with numbers from this project rather than by citing convention.

    python metric_justification.py
    AIFUZZ_RESULTS=results.jsonl python metric_justification.py
"""
import json
import os
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "eval_out" / (os.getenv("AIFUZZ_RESULTS") or "results.jsonl")
ARMS = [("random", "A  - Random (manual template)"),
        ("ai-seed", "B1 - AI-guided inputs"),
        ("ai-seed-cot", "B1-CoT - AI-guided inputs, planned"),
        ("ai", "B2 - AI-authored harness"),
        ("ai-full", "B3 - Full AI pipeline")]


def load():
    """One row per (arm, contract). The B1 arm was run twice, so later rows overwrite
    earlier ones -- the same de-duplication make_figures.py applies, kept identical here so
    the two scripts can never disagree."""
    rows = [json.loads(l) for l in RESULTS.read_text(encoding="utf-8").splitlines() if l.strip()]
    d = {}
    for r in rows:
        d[(r["approach"], r["id"])] = r
    return d


def score(labels, preds):
    """labels/preds are 1 = vulnerable, 0 = clean."""
    tp = sum(1 for l, p in zip(labels, preds) if l == 1 and p == 1)
    fp = sum(1 for l, p in zip(labels, preds) if l == 0 and p == 1)
    fn = sum(1 for l, p in zip(labels, preds) if l == 1 and p == 0)
    tn = sum(1 for l, p in zip(labels, preds) if l == 0 and p == 0)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc = (tp + tn) / len(labels) if labels else 0.0
    return dict(TP=tp, FP=fp, TN=tn, FN=fn, acc=acc, prec=prec, rec=rec, f1=f1)


def row(name, m):
    return (f"{name:<34} {m['TP']:>4} {m['FP']:>4} {m['TN']:>5} {m['FN']:>4} "
            f"{m['acc']:>9.3f} {m['prec']:>10.3f} {m['rec']:>8.3f} {m['f1']:>7.3f}")


HEAD = (f"{'detector':<34} {'TP':>4} {'FP':>4} {'TN':>5} {'FN':>4} "
        f"{'accuracy':>9} {'precision':>10} {'recall':>8} {'F1':>7}")


def main() -> int:
    d = load()
    ids = sorted({i for (_, i) in d})
    base = {i: d[("random", i)] for i in ids if ("random", i) in d}
    labels = [base[i]["label"] for i in sorted(base)]
    n, pos = len(labels), sum(labels)
    neg = n - pos

    print(__doc__.split("\n\n")[1].strip(), "\n")
    print("=" * 104)
    print("1. THE TEST SET IS IMBALANCED -- which is what makes accuracy the wrong headline")
    print("=" * 104)
    print(f"  contracts             {n}")
    print(f"  vulnerable (label=1)  {pos:>4}   {pos / n:6.1%}")
    print(f"  clean      (label=0)  {neg:>4}   {neg / n:6.1%}")
    print(f"\n  A detector that simply answers CLEAN every time is right {neg / n:.1%} of the time")
    print("  while finding zero vulnerabilities. Accuracy cannot tell that detector apart")
    print("  from a good one, so it is reported here only alongside the others, never alone.")

    print("\n" + "=" * 104)
    print("2. TRIVIAL DETECTORS vs THE REAL ARMS -- same contracts, same labels")
    print("=" * 104)
    print(HEAD)
    print("-" * 104)

    always_clean = score(labels, [0] * n)
    always_vuln = score(labels, [1] * n)
    rng = random.Random(0)
    coin = score(labels, [rng.randint(0, 1) for _ in range(n)])

    print(row("never flags anything", always_clean))
    print(row("flags everything", always_vuln))
    print(row("fair coin flip (seed 0)", coin))
    print("-" * 104)

    for key, title in ARMS:
        rs = {i: d[(key, i)] for i in ids if (key, i) in d}
        if not rs:
            continue
        ls = [rs[i]["label"] for i in sorted(rs)]
        ps = [1 if rs[i]["verdict"] == "bug-found" else 0 for i in sorted(rs)]
        print(row(title, score(ls, ps)))

    print("\n  Read the 'never flags anything' line against the arms. Its ACCURACY beats every")
    print("  real arm, and its RECALL and F1 are zero. That single row is the justification:")
    print("  accuracy ranks a useless detector first, precision/recall/F1 rank it last.")

    print("\n" + "=" * 104)
    print("3. WHY BOTH PRECISION AND RECALL, AND WHY F1 COMBINES THEM")
    print("=" * 104)
    print("  precision = TP/(TP+FP)  of the contracts flagged, how many were really vulnerable")
    print("                          -> low precision means an auditor wastes time on false alarms")
    print("  recall    = TP/(TP+FN)  of the vulnerable contracts, how many were caught")
    print("                          -> low recall means a real vulnerability ships to mainnet")
    print("\n  Either alone is trivially gamed: 'flags everything' scores recall "
          f"{always_vuln['rec']:.3f}, and any")
    print("  detector that flags a single contract it is sure about scores precision 1.000.")
    print("  F1 is their HARMONIC mean, which collapses toward the weaker of the two, so a")
    print("  detector cannot buy a good score by sacrificing one for the other:\n")
    print(f"  {'precision':>10} {'recall':>8} {'arithmetic mean':>17} {'F1 (harmonic)':>15}")
    for p, r in ((1.0, 0.02), (0.5, 0.5), (0.957, 0.564), (1.0, 0.564)):
        f1 = 2 * p * r / (p + r) if p + r else 0.0
        print(f"  {p:>10.3f} {r:>8.3f} {(p + r) / 2:>17.3f} {f1:>15.3f}")
    print("\n  Row 1 is the 'flag one contract you are certain about' detector. The arithmetic")
    print("  mean calls it 0.510 -- comparable to a balanced detector. F1 calls it 0.039.")

    print("\n" + "=" * 104)
    print("4. WHAT THIS PROJECT REPORTS, AND WHY")
    print("=" * 104)
    print("  precision  a security tool that cries wolf stops being used; this is the metric")
    print("             the AI arm actually improves (A 0.957 -> B1 1.000)")
    print("  recall     the safety-critical direction: a missed vulnerability is the failure")
    print("             mode that costs money on-chain")
    print("  F1         the single comparable number across arms, resistant to gaming")
    print("  accuracy   reported in metrics.csv for completeness, never as the headline,")
    print(f"             because {neg / n:.1%} of it is available for free on this test set")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
