#!/usr/bin/env python3
"""Live progress of the four-arm sweep. Run:  python progress.py"""
import json, os, time
from pathlib import Path
from collections import Counter

TOOL = Path(__file__).resolve().parent
ARMS = [("random", "A  Random (baseline)"), ("ai-seed", "B1 AI inputs"),
        ("ai-seed-cot", "B1-CoT AI inputs, planned"),
        ("ai", "B2 AI harness"), ("ai-full", "B3 Full AI pipeline")]
TOTAL = 678

rs = [json.loads(l) for l in (TOOL / "eval_out" / "results.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
d = {}
for r in rs:
    d[(r["approach"], r["id"])] = r

print("=" * 78)
print(f"{'ARM':<24}{'DONE':>11}{'BUILT':>9}{'COV':>8}{'TP':>7}{'FP':>6}{'ETA':>10}")
print("-" * 78)
for arm, label in ARMS:
    a = [v for (ap, _), v in d.items() if ap == arm]
    if not a:
        print(f"{label:<24}{'0/678':>11}{'-':>9}{'-':>8}{'-':>7}{'-':>6}{'queued':>10}")
        continue
    V = [r for r in a if r["label"] == 1]
    C = [r for r in a if r["label"] == 0]
    tp = sum(1 for r in V if r["verdict"] == "bug-found")
    fp = sum(1 for r in C if r["verdict"] == "bug-found")
    built = sum(1 for r in a if r["harness"] not in (None, "none"))
    cov = [r["target_cov_pct"] for r in a if r.get("target_cov_pct") is not None]
    # ETA from a TRAILING window: the run-wide mean is dragged down by fast early
    # contracts and understated the remaining time by ~3x on the B2 arm.
    times = [(r.get("gen_seconds") or 0) + (r.get("seconds") or 0) for r in a]
    window = times[-60:] if len(times) >= 60 else times
    per = sum(window) / len(window) if window else 0
    eta = (TOTAL - len(a)) * per / 3600
    print(f"{label:<24}{f'{len(a)}/{TOTAL}':>11}{built:>9}"
          f"{(sum(cov)/len(cov) if cov else 0):>7.1f}%{tp:>7}{fp:>6}"
          f"{('done' if len(a) >= TOTAL else f'{eta:.1f}h'):>10}")
print("=" * 78)

p = TOOL / "eval_out" / "PROGRESS.txt"
if p.exists():
    print("\nRun log:")
    for line in p.read_text(encoding="utf-8").splitlines():
        print("  " + line)

for arm, label in ARMS[1:]:
    lg = TOOL / "eval_out" / f"log_{arm}.txt"
    if lg.exists():
        lines = [l for l in lg.read_text(encoding="utf-8", errors="replace").splitlines() if l.startswith("[")]
        if lines:
            print(f"\nLatest [{label}]: {lines[-1][:110]}")
