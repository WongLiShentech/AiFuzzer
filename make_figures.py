#!/usr/bin/env python3
"""Per-arm confusion matrices + a combined comparison panel.

One PNG per arm that has data, plus a single side-by-side figure for the report. Arms still
queued are drawn as an explicit "no data yet" placeholder rather than silently omitted, so a
missing arm is visible in the figure instead of being mistaken for a zero result.

    python make_figures.py                      # uses eval_out/results.jsonl
    AIFUZZ_RESULTS=results_for_report.jsonl python make_figures.py
"""
import json
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

TOOL = Path(__file__).resolve().parent
OUT = TOOL / "eval_results"
OUT.mkdir(exist_ok=True)
RESULTS = TOOL / "eval_out" / (os.getenv("AIFUZZ_RESULTS") or "results.jsonl")
TOTAL = 678

ARMS = [
    ("random",  "A - Random (manual template)", "#5B8DEF"),
    ("ai-seed", "B1 - AI-guided inputs",        "#E8833A"),
    ("ai",      "B2 - AI-authored harness",     "#7A5FBF"),
    ("ai-full", "B3 - Full AI pipeline",        "#2E9E7E"),
]


def load():
    rows = [json.loads(l) for l in RESULTS.read_text(encoding="utf-8").splitlines() if l.strip()]
    d = {}
    for r in rows:
        d[(r["approach"], r["id"])] = r
    return d


def matrix(rows):
    V = [r for r in rows if r["label"] == 1]
    C = [r for r in rows if r["label"] == 0]
    tp = sum(1 for r in V if r["verdict"] == "bug-found")
    fp = sum(1 for r in C if r["verdict"] == "bug-found")
    fn, tn = len(V) - tp, len(C) - fp
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    cov = [r["target_cov_pct"] for r in rows if r.get("target_cov_pct") is not None]
    return dict(TP=tp, FP=fp, TN=tn, FN=fn, n=len(rows), prec=prec, rec=rec, f1=f1,
                acc=(tp + tn) / len(rows) if rows else 0.0,
                cov=(sum(cov) / len(cov)) if cov else 0.0)


def draw(ax, m, title, colour, partial):
    grid = np.array([[m["TN"], m["FP"]], [m["FN"], m["TP"]]])
    cmap = matplotlib.colors.LinearSegmentedColormap.from_list("c", ["#ffffff", colour])
    ax.imshow(grid, cmap=cmap, vmin=0, vmax=max(grid.max(), 1))
    ax.set_xticks([0, 1], ["predicted\nCLEAN", "predicted\nVULNERABLE"], fontsize=9)
    ax.set_yticks([0, 1], ["actual\nCLEAN", "actual\nVULNERABLE"], fontsize=9)
    lab = [[f"TN\n{m['TN']}", f"FP\n{m['FP']}"], [f"FN\n{m['FN']}", f"TP\n{m['TP']}"]]
    for i in range(2):
        for j in range(2):
            ax.text(j, i, lab[i][j], ha="center", va="center", fontsize=13, fontweight="bold",
                    color="white" if grid[i, j] > grid.max() * 0.55 else "#222")
    sub = (f"n={m['n']}"
           + (f"/{TOTAL} (PARTIAL)" if partial else "")
           + f"   P={m['prec']:.3f}  R={m['rec']:.3f}  F1={m['f1']:.3f}  cov={m['cov']:.1f}%")
    ax.set_title(f"{title}\n{sub}", fontsize=10, fontweight="bold", pad=9)


def placeholder(ax, title):
    ax.set_xticks([]); ax.set_yticks([])
    for s in ax.spines.values():
        s.set_edgecolor("#bbb"); s.set_linestyle("--")
    ax.text(0.5, 0.5, "no data yet\n(arm queued)", ha="center", va="center",
            fontsize=11, color="#888", transform=ax.transAxes)
    ax.set_title(f"{title}\n—", fontsize=10, fontweight="bold", pad=9)


CLASSES = ("reentrancy", "access-control", "ordering-attacks", "oracle-manipulation", "clean")


def per_class(rows):
    out = {}
    for cls in CLASSES:
        g = [r for r in rows if r["cls"] == cls]
        cov = [r["target_cov_pct"] for r in g if r.get("target_cov_pct") is not None]
        det = sum(1 for r in g if r["verdict"] == "bug-found")
        out[cls] = dict(n=len(g), cov=(sum(cov) / len(cov)) if cov else 0.0, det=det)
    return out


def build_rate(rows):
    return sum(1 for r in rows if r["harness"] not in (None, "none")) / len(rows) if rows else 0.0


def gen_secs(rows):
    g = [r.get("gen_seconds") or 0 for r in rows]
    return sum(g) / len(g) if g else 0.0


def multi_metric_chart(d, path):
    """Grouped bars over all arms with data. This is the figure that makes B2 visible: the
    detection metrics collapse where the LLM writes the harness, which the 2-arm chart hid."""
    arms = [(k, t, c) for (k, t, c) in ARMS if any(a == k for (a, _) in d)]
    names = ["Precision", "Recall", "F1", "Coverage", "Build rate"]
    fig, ax = plt.subplots(figsize=(11, 5.4))
    w = 0.8 / len(arms)
    x = np.arange(len(names))
    for i, (key, title, colour) in enumerate(arms):
        rows = [v for (a, _), v in d.items() if a == key]
        m = matrix(rows)
        vals = [m["prec"], m["rec"], m["f1"], m["cov"] / 100, build_rate(rows)]
        partial = len(rows) < TOTAL
        bars = ax.bar(x + (i - (len(arms) - 1) / 2) * w, vals, w,
                      label=title.split(" - ")[0] + (" (partial)" if partial else ""),
                      color=colour, hatch="//" if partial else None, edgecolor="white")
        for b, v in zip(bars, vals):
            # 3 dp, not 2: at 2 dp A's coverage (66.54%) and B1's (67.03%) both render as
            # "0.67" and the arms look identical, and precision 0.957 flattens to 0.96 against
            # a true 1.000. The differences here are real but sub-1%, so the label has to
            # resolve them or the figure understates its own result.
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.012,
                    f"{v:.3f}", ha="center", fontsize=7)
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("score (0-1)")
    ax.set_xticks(x, names)
    ax.legend(fontsize=9, ncol=len(arms))
    ax.axhline(0.8, ls="--", lw=0.8, color="grey", alpha=0.5)
    ax.set_title(f"AI-guided vs manual fuzzing (n={TOTAL})",
                 fontweight="bold")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def multi_coverage_chart(d, path):
    arms = [(k, t, c) for (k, t, c) in ARMS if any(a == k for (a, _) in d)]
    fig, ax = plt.subplots(figsize=(11, 5.4))
    w = 0.8 / len(arms)
    x = np.arange(len(CLASSES))
    for i, (key, title, colour) in enumerate(arms):
        rows = [v for (a, _), v in d.items() if a == key]
        pc = per_class(rows)
        vals = [pc[c]["cov"] for c in CLASSES]
        partial = len(rows) < TOTAL
        ax.bar(x + (i - (len(arms) - 1) / 2) * w, vals, w,
               label=title.split(" - ")[0] + (" (partial)" if partial else ""),
               color=colour, hatch="//" if partial else None, edgecolor="white")
    ax.set_ylim(0, 100)
    ax.set_ylabel("mean target coverage %")
    ax.set_xticks(x, [c.replace("-", "\n") for c in CLASSES])
    ax.legend(fontsize=9, ncol=len(arms))
    ax.set_title(f"Code coverage by vulnerability type (n={TOTAL})", fontweight="bold")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def seed_delivery_chart(d, path):
    """Why the B1 null result is bounded before detection is even considered: half the arm ran
    on an empty corpus, and the vulnerable contracts it missed were coverage-limited rather than
    seed-limited. Neither fact is visible in the detection metrics, so it needs its own figure."""
    rows = [v for (a, _), v in d.items() if a == "ai-seed"]
    if not rows:
        return False
    built = [r for r in rows if r["harness"] not in (None, "none")]
    seeded = [r for r in built if (r.get("ai_seeds") or 0) > 0]
    vuln = [r for r in rows if r["label"] == 1]
    found = [r for r in vuln if r["verdict"] == "bug-found"]
    missed = [r for r in vuln if r["verdict"] != "bug-found"]
    cov = lambda g: ([r["target_cov_pct"] for r in g if r.get("target_cov_pct") is not None] or [0])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.4))

    # left: how far the treatment actually reached
    vals = [len(rows), len(built), len(seeded)]
    labs = [f"test set\n{len(rows)}", f"harness built\n{len(built)}", f"≥1 seed delivered\n{len(seeded)}"]
    bars = ax1.bar(range(3), vals, 0.6, color=["#c9d3e0", "#5B8DEF", "#E8833A"], edgecolor="white")
    for b, v in zip(bars, vals):
        ax1.text(b.get_x() + b.get_width() / 2, v + 8, f"{100 * v / len(rows):.1f}%",
                 ha="center", fontsize=9, fontweight="bold")
    ax1.set_xticks(range(3), labs, fontsize=9)
    ax1.set_ylim(0, len(rows) * 1.15)
    ax1.set_ylabel("contracts")
    ax1.set_title("Arm B1: how far the treatment reached", fontsize=11, fontweight="bold")

    # right: the misses are coverage-limited, not seed-limited
    mf, mm = sum(cov(found)) / len(cov(found)), sum(cov(missed)) / len(cov(missed))
    bars = ax2.bar([0, 1], [mf, mm], 0.55, color=["#2E9E7E", "#f85149"], edgecolor="white")
    for b, v in zip(bars, (mf, mm)):
        ax2.text(b.get_x() + b.get_width() / 2, v + 1.5, f"{v:.1f}%", ha="center",
                 fontsize=10, fontweight="bold")
    ax2.set_xticks([0, 1], [f"detected\n(n={len(found)})", f"missed\n(n={len(missed)})"], fontsize=9)
    ax2.set_ylim(0, 100)
    ax2.set_ylabel("mean target coverage %")
    ax2.set_title("Vulnerable contracts: coverage on hits vs misses", fontsize=11, fontweight="bold")

    fig.suptitle("Why AI-guided seeding could not move detection on this benchmark",
                 fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return True


def cost_chart(d, path):
    """The cost axis the metric charts don't show: build rate vs generation time (log). This is
    where AI-authored harness generation looks worst - ~half the build rate at ~700x the cost."""
    arms = [(k, t, c) for (k, t, c) in ARMS if any(a == k for (a, _) in d)]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 4.8))
    labels = [t.split(" - ")[0] for (_, t, _) in arms]
    colours = [c for (_, _, c) in arms]
    br = [build_rate([v for (a, _), v in d.items() if a == k]) * 100 for (k, _, _) in arms]
    gt = [max(gen_secs([v for (a, _), v in d.items() if a == k]), 0.1) for (k, _, _) in arms]
    for ax, vals, ttl, ylab, log in [(a1, br, "Harness build rate", "% of contracts", False),
                                     (a2, gt, "Mean setup time / contract", "seconds (log)", True)]:
        bars = ax.bar(labels, vals, color=colours, edgecolor="white")
        if log:
            ax.set_yscale("log")
        ax.set_title(ttl, fontweight="bold")
        ax.set_ylabel(ylab)
        ax.tick_params(axis="x", labelsize=8)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, b.get_height(),
                    (f"{v:.0f}%" if not log else (f"{v:.1f}s" if v < 10 else f"{v:.0f}s")),
                    ha="center", va="bottom", fontsize=8)
    fig.suptitle("Why AI-authored harnesses lose: cost and reliability", fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(path, dpi=150)
    plt.close(fig)


def main():
    global ARMS
    # Optional arm filter: AIFUZZ_ARMS="random,ai-seed,ai" renders only those arms (e.g. to make
    # a clean complete-arms-only comparison that excludes a still-partial B3). AIFUZZ_TAG suffixes
    # the combined-panel filenames so a filtered run doesn't overwrite the full 4-arm figures.
    only = os.getenv("AIFUZZ_ARMS")
    if only:
        keys = {k.strip() for k in only.split(",")}
        ARMS = [a for a in ARMS if a[0] in keys]
    sfx = os.getenv("AIFUZZ_TAG", "")

    d = load()
    present = []
    for key, title, colour in ARMS:
        rows = [v for (a, _), v in d.items() if a == key]
        # one figure per arm
        fig, ax = plt.subplots(figsize=(4.6, 4.4))
        if rows:
            m = matrix(rows)
            draw(ax, m, title, colour, partial=len(rows) < TOTAL)
            present.append((key, title, colour, m, len(rows) < TOTAL))
        else:
            placeholder(ax, title)
        fig.tight_layout()
        fig.savefig(OUT / f"cm_{key}.png", dpi=150)
        plt.close(fig)
        print(f"  wrote cm_{key}.png" + ("" if rows else "  (placeholder - no data)"))

    # combined panel
    fig, axes = plt.subplots(1, len(ARMS), figsize=(4.5 * len(ARMS), 4.6))
    for ax, (key, title, colour) in zip(axes, ARMS):
        rows = [v for (a, _), v in d.items() if a == key]
        if rows:
            draw(ax, matrix(rows), title, colour, partial=len(rows) < TOTAL)
        else:
            placeholder(ax, title)
    fig.suptitle(f"Confusion matrices - AI-guided vs manual (random) fuzzing (n={TOTAL})",
                 fontsize=13, fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    fig.savefig(OUT / f"cm_all_arms{sfx}.png", dpi=150)
    plt.close(fig)
    print(f"  wrote cm_all_arms{sfx}.png")

    multi_metric_chart(d, OUT / f"metrics_all_arms{sfx}.png"); print(f"  wrote metrics_all_arms{sfx}.png")
    multi_coverage_chart(d, OUT / f"coverage_all_arms{sfx}.png"); print(f"  wrote coverage_all_arms{sfx}.png")
    cost_chart(d, OUT / f"cost_all_arms{sfx}.png"); print(f"  wrote cost_all_arms{sfx}.png")
    if seed_delivery_chart(d, OUT / f"seed_delivery{sfx}.png"):
        print(f"  wrote seed_delivery{sfx}.png")

    print(f"\n{'ARM':<32}{'n':>7}{'TP':>5}{'FP':>5}{'TN':>6}{'FN':>5}{'P':>8}{'R':>8}{'F1':>8}{'cov':>8}")
    print("-" * 92)
    for key, title, _, m, partial in present:
        print(f"{title + (' [PARTIAL]' if partial else ''):<32}{m['n']:>7}{m['TP']:>5}{m['FP']:>5}"
              f"{m['TN']:>6}{m['FN']:>5}{m['prec']:>8.3f}{m['rec']:>8.3f}{m['f1']:>8.3f}{m['cov']:>7.1f}%")


if __name__ == "__main__":
    main()
