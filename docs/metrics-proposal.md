# Metrics for comparing AI-guided vs random fuzzing

## Fair-comparison protocol

A credible comparison changes only one variable (random vs AI-guided input
generation) and holds everything else constant. `benchmark_testset.py` already does this:

- **same** contracts, harnesses, and oracles (the labelled registry),
- **same** transaction budget per mode (`ECHIDNA_TEST_LIMIT`),
- **multiple trials** per mode — fuzzing is stochastic, so we report
  **mean ± stdev**, never a single lucky run.

Clean contracts supply the true-negatives, so false positives are measurable.

## The five metrics (each weighted 20%)

Each metric is normalized to `[0, 1]` where `1` is best, so they can be combined
into one score.

| Metric | Raw | Direction | Normalized component |
|---|---|---|---|
| F1 | 0–1 | higher better | `F1` (as is) |
| FPR (false-positive rate) | 0–1 | lower better | `1 − FPR` |
| Code coverage | `cov:` count | higher better | `cov / max(cov_random, cov_ai)` |
| Bugs found | TP count | higher better | `TP / N_vulnerable` (= recall) |
| Time taken | seconds | lower better | `t_min / t_this` (faster → 1.0) |

Coverage and time normalize **head-to-head** (relative to the two modes), so the
better mode scores `1.0` on that axis and the other a fraction.

## Composite score

```
Score = 100 × ( 0.2·F1 + 0.2·(1−FPR) + 0.2·CovNorm + 0.2·BugsNorm + 0.2·TimeNorm )
```

A single 0–100 number per mode; the comparison is Random vs AI-guided, reported as
mean ± stdev over trials. `benchmark_testset.py` prints this as the `Composite score`
row and writes it to `results/benchmark.json`.

## Honest note on metric overlap

F1, FPR, and Bugs-found all measure detection quality and partly overlap (F1
blends precision and recall; bugs/N is recall; FPR is the false-alarm side). So a
flat 5×20% split implicitly weights **detection ≈ 60% / coverage 20% / speed
20%**. That is defensible (detection is the point), but if a cleaner, orthogonal
weighting is preferred, group by dimension instead:

| Dimension | Metric(s) | Weight |
|---|---|---|
| Detection | F1 (and/or bugs + FPR) | e.g. 50% |
| Thoroughness | code coverage | e.g. 25% |
| Efficiency | time-to-result | e.g. 25% |

Primary proposal: the simple 5×20%; the dimension split is the fallback if
double-counting is a concern.

## Status

- **Available now (random baseline):** bugs found, precision, recall, F1, FPR,
  code coverage, time — all over multiple trials.
- **AI-guided columns:** all four arms (A, B1, B2, B3) run from the same script and
  produce the full comparison.
