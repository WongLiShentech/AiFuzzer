#!/usr/bin/env python3
"""Evaluation harness — proves the tool works (deliverable #3 evidence).

Runs aifuzz over the labeled dataset (dataset/labels.csv) in both modes and
computes the headline comparison:

  * random vs AI-guided: coverage reached and vulnerabilities found.
  * detection quality vs ground truth: Precision / Recall / F1 / FPR
    (clean contracts provide the true-negatives for FPR).

This is the methodology informed by the reference paper (docs/reference-paper.pdf),
applied to *our* tool — not the product itself. Results are written to
results/ (gitignored).

Status: scaffold (Milestone M5). The metric math below is real; it is fed by
engine output once M2/M3 land.
"""

from __future__ import annotations

import csv
from pathlib import Path

REPO = Path(__file__).resolve().parent
LABELS = REPO / "dataset" / "labels.csv"
RESULTS = REPO / "results"


def load_ground_truth() -> list[dict[str, str]]:
    with LABELS.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def prf(tp: int, fp: int, fn: int, tn: int) -> dict[str, float]:
    """Precision / Recall / F1 / FPR from a confusion matrix (real math)."""
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": fpr}


def main() -> int:
    rows = load_ground_truth()
    vulnerable = sum(1 for r in rows if r["label"] == "1")
    clean = sum(1 for r in rows if r["label"] == "0")
    print(f"[benchmark] dataset: {len(rows)} contracts ({vulnerable} vulnerable, {clean} clean)")
    print("[benchmark] scaffold (M5): wire up aifuzz random vs AI-guided runs, then score with prf().")
    RESULTS.mkdir(exist_ok=True)
    raise SystemExit("TODO(M5): run engines over dataset and emit results/ metrics")


if __name__ == "__main__":
    main()
