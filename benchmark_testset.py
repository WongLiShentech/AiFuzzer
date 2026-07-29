#!/usr/bin/env python3
"""Held-out test-set benchmark: baseline random fuzzing vs raw-Qwen+RAG.

Two approaches over every DATASET_SPLIT:test contract:
  random : synthesize.py template harness -> Echidna (stock, random inputs, no AI)
  ai     : raw qwen2.5-coder:7b + RAG over the 4746 reference split -> harness, with a
           compile-check -> feed-error-back -> retry loop (<=3 attempts). No fine-tuning.
Identical fuzzing settings for both. Per-contract verdict in
{gen-fail, compile-fail, no-bug, bug-found}. Confusion matrix reconciles to the count.
Checkpoints every contract to eval_out/results.jsonl and resumes from it.

Reproduce (full run):   python benchmark_testset.py --approach both
Iteration-0 smoke:      python benchmark_testset.py --approach both --limit 5
Rebuild table only:     python benchmark_testset.py --summary-only
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from collections import defaultdict
from pathlib import Path

TOOL = Path(__file__).resolve().parent
DS = Path(os.getenv("DATASET_DIR", "C:/smart-contracts"))
OUT = TOOL / "eval_out"
SCRATCH = TOOL / "_eval"
RESULTS = OUT / "results.jsonl"
SUMMARY = OUT / "summary.md"
CHROMA = TOOL / "chroma_data"
OLLAMA = os.getenv("OLLAMA_BIN", r"C:\Users\wongl\AppData\Local\Programs\Ollama\ollama.exe")
SVC = "aifuzz"

MINOR = {"0.4": "0.4.26", "0.5": "0.5.17", "0.6": "0.6.12", "0.7": "0.7.6", "0.8": "0.8.25"}


def solc_for(pragma: str) -> str:
    p = pragma.replace(" ", "")
    # exact pin -> use that precise version (solc-select installs it on demand). Covers
    # bare `0.4.25` and standalone `=0.6.11` -- but NOT the `=` inside `>=`/`<=` (a bound,
    # not a pin), and not flattened files whose first token is `=X` still followed by ranges.
    if re.fullmatch(r"\d+\.\d+\.\d+", p):
        return p
    m = re.search(r"(?<![<>])=(\d+\.\d+\.\d+)", p)
    if m:
        return m.group(1)
    # upper-bounded range (`<0.6.0`): pick the highest minor we ship BELOW the cap, so a
    # `>=0.4.21 <0.6.0` contract that uses 0.5-only syntax (e.g. `address payable`) isn't
    # miscompiled with 0.4.
    m = re.search(r"<0\.(\d)", p)
    if m:
        for minor in range(int(m.group(1)) - 1, 3, -1):
            if f"0.{minor}" in MINOR:
                return MINOR[f"0.{minor}"]
    for minor in ("0.8", "0.7", "0.6", "0.5", "0.4"):
        if minor in p:
            return MINOR[minor]
    return "0.8.25"


def pragma_of(src: str) -> str:
    m = re.search(r"pragma solidity ([^;]+);", src)
    return m.group(1).strip() if m else "^0.8.0"


def main_contract(src: str):
    for name in re.findall(r"\bcontract\s+(\w+)", src):
        if re.search(rf"contract\s+{name}\b.*?echidna_\w+", src, re.S):
            return name
    names = re.findall(r"\bcontract\s+(\w+)", src)
    return names[-1] if names else None


# ------------------------------------------------------------ preflight checklist
def preflight():
    tag = subprocess.run([OLLAMA, "list"], capture_output=True, encoding="utf-8", errors="replace").stdout
    assert "qwen2.5-coder:7b" in tag, "ABORT: qwen2.5-coder:7b not in ollama"
    print("[preflight] model: qwen2.5-coder:7b (weights untouched, no fine-tuning)")
    import chromadb
    col = chromadb.PersistentClient(path=str(CHROMA)).get_or_create_collection("aifuzz-knowledge")
    n = col.count()
    assert n == 4746, f"ABORT: RAG count {n} != 4746 (must be reference-only)"
    print(f"[preflight] RAG count: {n} (reference split only; _quarantine + test excluded)")
    for p in DS.rglob("*.sol"):
        if "_quarantine" in p.parts:
            continue
        if "DATASET_SPLIT: test" in p.read_text(encoding="utf-8", errors="replace"):
            assert not col.get(ids=[p.relative_to(DS).as_posix()])["ids"], "ABORT: a test contract is in the RAG"
            break
    print("[preflight] held-out isolation: no test contract embedded in RAG")
    subprocess.run(["docker", "compose", "up", "-d", SVC], cwd=str(TOOL), capture_output=True, encoding="utf-8", errors="replace")
    ps = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, encoding="utf-8", errors="replace").stdout
    assert SVC in ps, f"ABORT: {SVC} container not running"
    print(f"[preflight] Echidna container up ({[x for x in ps.split() if SVC in x]})")


# ------------------------------------------------------------ test-set loading
def load_test_contracts(limit=None):
    out = []
    for p in sorted(DS.rglob("*.sol")):
        if "_quarantine" in p.parts:
            continue
        t = p.read_text(encoding="utf-8", errors="replace")
        if "DATASET_SPLIT: test" not in t:
            continue
        label = 0 if re.search(r"GROUND_TRUTH_LABEL:\s*0", t) else 1
        mc = re.search(r"PRIMARY_TYPE:\s*([\w-]+)", t)
        cls = "clean" if label == 0 else (mc.group(1) if mc else "unknown")
        # A few oracle contracts ship WITH their own echidna_ invariant (a pre-written harness).
        # Fuzzing that would credit neither arm's harness generation -- both would just run the
        # baked-in answer. Strip it so the contract is a RAW target and the tool must earn it.
        pre_harnessed = "echidna_" in t
        if pre_harnessed:
            t = re.sub(r"\n[ \t]*function\s+echidna_\w+\s*\([^)]*\)[^{]*\{[^}]*\}", "", t)
        out.append({"path": p, "id": p.relative_to(DS).as_posix(), "label": label,
                    "cls": cls, "is_harness": False, "pre_harnessed": pre_harnessed, "src": t})
    out.sort(key=lambda c: (c["cls"], c["id"]))
    if limit:  # smoke: spread across classes
        by = defaultdict(list)
        for c in out:
            by[c["cls"]].append(c)
        picked = []
        while len(picked) < limit and any(by.values()):
            for k in list(by):
                if by[k] and len(picked) < limit:
                    picked.append(by[k].pop(0))
        return picked
    return out


# ------------------------------------------------------------ harness building
def random_harness(c):
    """Approach A (random/baseline). Coverage-forwarding harness (exposes the target's whole
    public surface so Echidna explores it) is the default; the shape template is a fallback
    when no forwardable surface builds. Oracle harness = the contract itself."""
    if c["is_harness"]:
        return c["src"], main_contract(c["src"]), "self", 0
    imp = "./" + c["path"].name
    from aifuzz.synthesize import synthesize_coverage_harness, synthesize_harness
    cov = synthesize_coverage_harness(c["src"], imp)
    if cov:
        return cov[0], cov[1], "coverage", 0
    syn = synthesize_harness(c["src"], imp)
    if syn.built:
        return syn.harness_src, syn.harness_name, "template", 0
    return None, None, "none", 0


def ai_seed_harness(c, pg):
    """Approach B1 (AI-guided INPUT generation) -- the project's actual research question.
    The harness is byte-identical to the random arm, so harness quality is held constant and
    the ONLY variable is where the transaction sequences come from: Echidna's random sampler
    versus LLM-proposed sequences replayed as a seed corpus. Returns the harness plus the
    seeds; a seeding failure degrades to plain random fuzzing (reported via ai_seeds=0), which
    is honest -- it means the AI contributed nothing on that contract, not that the run broke."""
    hsrc, cname, _, _ = random_harness(c)
    if not hsrc:
        return None, None, "none", 0, []
    if pg is None:      # loud: a silently-None generator once made a whole arm produce zero seeds
        raise RuntimeError("ai-seed arm requires a PropertyGenerator; got None")
    seeds = []
    try:
        from aifuzz.synthesize import coverage_forwarder_specs
        spec = coverage_forwarder_specs(c["src"])
        if spec:
            seeds = pg.seed_sequences(c["src"], spec[1])
    except Exception as e:
        print(f"    [seed-fail] {c['path'].name}: {str(e)[:120]}")
        seeds = []
    return hsrc, cname, "ai-seeded", 0, seeds


def ai_full_harness(c, pg):
    """Approach B3 (FULL AI pipeline) -- the configuration the project's design specifies: RAG
    grounds BOTH generation stages. The model writes the harness (as B2) AND proposes the
    transaction sequences that seed Echidna's corpus (as B1), so this is the arm a user of the
    tool actually runs. B1 and B2 exist to attribute any difference to one stage or the other;
    this one measures the product end to end. No template fallback -- if the model cannot produce
    a compiling harness the contract is a gen-fail, exactly as in B2."""
    hsrc, cname, _, att = ai_harness(c, pg)
    if not hsrc:
        return None, None, "none", att, []
    seeds = []
    try:
        from aifuzz.synthesize import coverage_forwarder_specs
        spec = coverage_forwarder_specs(c["src"])
        if spec:
            seeds = pg.seed_sequences(c["src"], spec[1])
    except Exception as e:
        print(f"    [seed-fail] {c['path'].name}: {str(e)[:120]}")
    return hsrc, cname, "ai-full", att, seeds


def ai_harness(c, pg):
    """Approach B2 (AI-authored harness) = PURE LLM. The model READS the contract and writes an Echidna
    harness, retrying hard (generate -> compile -> repair, with varied sampling) until it
    produces a valid one or exhausts the budget. NO template fallback -- the AI arm must stand
    entirely on its own harness generation; a gen-fail is reported honestly, never masked by
    borrowing the random arm's template. This keeps the two arms genuinely distinct."""
    imp = "./" + c["path"].name
    res = pg.generate_harness(c["src"], imp)
    if res:
        harness, name, attempts = res
        return harness, name, "ai-llm", attempts
    return None, None, "none", 0


# ------------------------------------------------------------ fuzzing (Echidna in Docker)
def harness_is_payable(harness_src: str, cname: str) -> bool:
    """True if the harness contract's constructor is payable. Only then is it safe to fund
    it via balanceContract -- Echidna delivers the balance at deploy, and a non-payable
    constructor reverts on the funded deploy."""
    for pat in (rf"function\s+{re.escape(cname)}\s*\([^)]*\)([^{{]*)\{{",
                r"constructor\s*\([^)]*\)([^{]*)\{"):
        m = re.search(pat, harness_src)
        if m and "payable" in m.group(1):
            return True
    return False


def classify(o: str) -> str:
    """Map Echidna output to a verdict. A real bug is the end-of-run SUMMARY reporting a
    property `X: failed!` (a genuine counterexample). Broken harnesses instead report
    `failed with no transactions made` (the property reverts before any fuzzing), fail to
    deploy, or crash the shrinker -- none of which is a contract bug, so they get their own
    `harness-invalid` verdict rather than being miscounted as bug-found.
    NB: streaming `Test X falsified!` lines appear for BOTH real and degenerate cases; only
    the summary `X: failed!` (with colon) distinguishes a true finding."""
    if re.search(r"echidna_\w+:\s*failed!", o):
        return "bug-found"
    if ("failed with no transactions made" in o
            or re.search(r"Deploying the contract.*failed", o)
            or "Prelude.init" in o
            or "crytic/echidna/issues" in o):
        return "harness-invalid"
    if re.search(r"echidna_\w+:\s*passed", o) or re.search(r"tests:\s*\d+/\d+", o) or "cov:" in o:
        return "no-bug"
    return "compile-fail"


def target_coverage(run_dir, target_name):
    """TARGET-ONLY line coverage from Echidna's LCOV, as (pct, hit, total).

    Echidna's `cov:` counts unique EVM instructions across ALL deployed codehashes
    (harness + helpers + target) with no denominator, so it is NOT comparable between arms
    whose harnesses differ in size. LCOV emits one `SF:` section per source file with a
    `DA:<line>,<hits>` record per INSTRUMENTED line, so we can score the target file alone.
    """
    corpus = run_dir / "corpus"
    lcovs = sorted(corpus.glob("covered.*.lcov")) if corpus.exists() else []
    if not lcovs:
        return None, None, None
    cur, hit, tot = None, 0, 0
    for line in lcovs[-1].read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("SF:"):
            cur = line[3:].strip().replace("\\", "/")
        elif line.startswith("end_of_record"):
            cur = None
        elif line.startswith("DA:") and cur and cur.endswith("/" + target_name):
            _, _, hits = line[3:].partition(",")
            tot += 1
            if hits.strip() not in ("0", ""):
                hit += 1
    if tot == 0:
        return None, 0, 0
    return round(100.0 * hit / tot, 1), hit, tot


def fuzz(harness_src, target_src, target_name, cname, test_limit, timeout, seeds=None):
    run = SCRATCH / "run"
    shutil.rmtree(run, ignore_errors=True)
    run.mkdir(parents=True, exist_ok=True)
    (run / target_name).write_text(target_src, encoding="utf-8")
    (run / "Harness.sol").write_text(harness_src, encoding="utf-8")
    if seeds:   # AI arm: pre-seed Echidna's corpus with AI-generated sequences (replayed on start)
        from aifuzz.ai_guidance import write_seed_corpus
        write_seed_corpus(run / "corpus", seeds)
    ver = solc_for(pragma_of(harness_src))
    # Fund the harness so value-sending setup/attacks don't revert (mirrors analyzer.py's
    # _SYNTH_CONFIG). Only for payable-ctor harnesses -- a non-payable ctor reverts on the
    # funded deploy, so those run unfunded as before.
    cfg = ""
    if harness_is_payable(harness_src, cname):
        (run / "config.yaml").write_text("balanceContract: 10000000000000000000\n", encoding="utf-8")
        cfg = "--config config.yaml "
    # SOLC_VERSION env (not `solc-select use`) is what crytic-compile actually honours;
    # otherwise it silently falls back to 0.8.25 and every old-pragma harness fails.
    inner = (f"cd /app/_eval/run && solc-select install {ver} >/dev/null 2>&1; "
             f"export SOLC_VERSION={ver}; "
             f"timeout {timeout} echidna Harness.sol --contract {cname} {cfg}--test-limit {test_limit} "
             f"--corpus-dir corpus 2>&1")
    t0 = time.time()
    proc = subprocess.run(["docker", "compose", "exec", "-T", SVC, "sh", "-c", inner],
                          cwd=str(TOOL), capture_output=True, encoding="utf-8", errors="replace")
    secs = round(time.time() - t0, 1)
    o = proc.stdout + proc.stderr
    covs = re.findall(r"cov:\s*(\d+)", o)
    cov = int(covs[-1]) if covs else None          # harness+target instrs -- NOT arm-comparable
    tpct, thit, ttot = target_coverage(run, target_name)   # target-only % -- the headline metric
    return classify(o), cov, tpct, thit, ttot, secs, o[-2500:]


def run_contract(c, approach, pg, test_limit, timeout):
    rec = {"approach": approach, "id": c["id"], "cls": c["cls"], "label": c["label"],
           "is_harness": c.get("is_harness"), "verdict": None, "harness": None,
           "harness_src": None, "echidna_tail": None, "attempts": 0, "coverage": None,
           "target_cov_pct": None, "target_lines_hit": None, "target_lines_total": None,
           "gen_seconds": None, "seconds": None, "error": None}
    try:
        g0 = time.time()
        tname = c["path"].name
        seeds = []
        if approach == "random":
            hsrc, cname, htype, att = random_harness(c)     # generic per-class template
        elif approach == "ai-seed":
            hsrc, cname, htype, att, seeds = ai_seed_harness(c, pg)   # same harness, AI seeds
        elif approach == "ai-full":
            hsrc, cname, htype, att, seeds = ai_full_harness(c, pg)   # AI harness + AI seeds
        else:
            hsrc, cname, htype, att = ai_harness(c, pg)      # pure LLM, distinct from random
        rec["gen_seconds"] = round(time.time() - g0, 1)
        rec["harness"], rec["attempts"], rec["harness_src"] = htype, att, hsrc
        rec["ai_seeds"] = len(seeds)
        if not hsrc or not cname:
            rec["verdict"] = "gen-fail"
            return rec
        (rec["verdict"], rec["coverage"], rec["target_cov_pct"], rec["target_lines_hit"],
         rec["target_lines_total"], rec["seconds"], rec["echidna_tail"]) = fuzz(
            hsrc, c["src"], tname, cname, test_limit, timeout, seeds=seeds or None)
    except Exception as e:  # never fatal to the batch
        rec["verdict"] = "gen-fail"
        rec["error"] = str(e)[:200]
    return rec


# ------------------------------------------------------------ checkpoint / resume
def load_done():
    done = set()
    if RESULTS.exists():
        for line in RESULTS.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
                done.add((r["approach"], r["id"]))
            except Exception:
                pass
    return done


def append(rec):
    with RESULTS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


# ------------------------------------------------------------ summary table
def summarize():
    raw = [json.loads(l) for l in RESULTS.read_text(encoding="utf-8").splitlines() if l.strip()]
    dedup = {}
    for r in raw:
        dedup[(r["approach"], r["id"])] = r   # last write wins (resume-safe)
    rows = list(dedup.values())
    lines = ["# Test-set benchmark summary", ""]
    for approach in ("random", "ai"):
        rs = [r for r in rows if r["approach"] == approach]
        if not rs:
            continue
        agg = defaultdict(lambda: dict(n=0, gen=0, comp=0, bug=0, tp=0, fp=0, fn=0, tn=0,
                                       retries=0, cov=[], tcov=[], t=[], bugt=[]))
        for r in rs:
            bug = r["verdict"] == "bug-found"
            for key in (r["cls"], "TOTAL"):
                a = agg[key]
                a["n"] += 1
                a["gen"] += r["harness"] not in (None, "none")
                a["comp"] += r["verdict"] in ("no-bug", "bug-found")
                a["bug"] += bug
                a["retries"] += bool(r.get("attempts", 0) and r["attempts"] > 1)
                if r.get("coverage") is not None:
                    a["cov"].append(r["coverage"])
                if r.get("target_cov_pct") is not None:
                    a["tcov"].append(r["target_cov_pct"])
                if r.get("seconds") is not None:
                    a["t"].append(r["seconds"])
                if bug and r.get("seconds") is not None:
                    a["bugt"].append(r["seconds"])
                if r["label"] == 1:
                    a["tp" if bug else "fn"] += 1
                else:
                    a["fp" if bug else "tn"] += 1
        lines += [f"## Approach: {approach}", "",
                  "| class | contracts | built | mean cov% (built) | mean cov% (all) | bug-found | TP | FP | FN | TN | Precision | Recall | F1 |",
                  "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for key in sorted(agg, key=lambda k: (k == "TOTAL", k)):
            a = agg[key]
            tp, fp, fn, tn = a["tp"], a["fp"], a["fn"], a["tn"]
            prec = tp / (tp + fp) if tp + fp else 0.0
            rec = tp / (tp + fn) if tp + fn else 0.0
            f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
            # Coverage headline: mean over contracts that BUILT a harness, and mean over ALL
            # (a no-build scores 0% -> the honest denominator for "coverage on the test set").
            cbuilt = (sum(a["tcov"]) / len(a["tcov"])) if a["tcov"] else 0.0
            call = (sum(a["tcov"]) / a["n"]) if a["n"] else 0.0
            lines.append(f"| {key} | {a['n']} | {a['gen']} | {cbuilt:.1f} | {call:.1f} | {a['bug']} | "
                         f"{tp} | {fp} | {fn} | {tn} | {prec:.3f} | {rec:.3f} | {f1:.3f} |")
        t = agg["TOTAL"]
        recon = t["tp"] + t["fp"] + t["fn"] + t["tn"]
        assert recon == t["n"], f"matrix does not reconcile: {recon} != {t['n']}"
        lines.append("")
        lines.append(f"- reconcile: TP+FP+FN+TN = {recon} == contracts {t['n']}  (OK)")
        if approach == "ai":
            lines.append(f"- contracts that needed a retry: {t['retries']}")
        if t["cov"]:
            lines.append(f"- mean coverage (raw echidna cov points): {sum(t['cov'])/len(t['cov']):.0f}")
        if t["bugt"]:
            lines.append(f"- mean time-to-bug (bug-found only): {sum(t['bugt'])/len(t['bugt']):.1f}s")
        if t["t"]:
            lines.append(f"- mean fuzz time / contract: {sum(t['t'])/len(t['t']):.1f}s")
        lines.append("")
    SUMMARY.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--approach", choices=["random", "ai", "ai-seed", "ai-full", "both"], default="both")
    ap.add_argument("--limit", type=int, default=None, help="smoke: only N contracts, spread across classes")
    ap.add_argument("--test-limit", type=int, default=int(os.getenv("BENCH_TEST_LIMIT", "5000")))
    ap.add_argument("--timeout", type=int, default=int(os.getenv("BENCH_TIMEOUT", "60")))
    ap.add_argument("--summary-only", action="store_true")
    ap.add_argument("--vuln-only", action="store_true",
                    help="only label==1 contracts (recall pass; clean/FP sweep runs separately)")
    ap.add_argument("--clean-sample", type=int, default=None, metavar="N",
                    help="all vulnerable + N clean sampled with a FIXED seed, so both arms "
                         "see an identical clean set and the run is reproducible")
    args = ap.parse_args()
    OUT.mkdir(exist_ok=True)
    if args.summary_only:
        summarize()
        return
    preflight()
    contracts = load_test_contracts(args.limit)
    if args.vuln_only:
        contracts = [c for c in contracts if c["label"] == 1]
    if args.clean_sample:
        import random as _rnd
        vuln = [c for c in contracts if c["label"] == 1]
        clean = sorted([c for c in contracts if c["label"] == 0], key=lambda c: c["id"])
        _rnd.Random(0).shuffle(clean)
        contracts = vuln + clean[:args.clean_sample]
        print(f"[sample] {len(vuln)} vulnerable + {len(clean[:args.clean_sample])} clean "
              f"(seed=0, sorted-then-shuffled -> identical for both arms)")
    approaches = ["random", "ai-seed", "ai", "ai-full"] if args.approach == "both" else [args.approach]
    pg = None
    if any(a.startswith("ai") for a in approaches):   # "ai" AND "ai-seed" both need the model
        from aifuzz.ai_guidance import PropertyGenerator
        pg = PropertyGenerator()
    done = load_done()
    total = len(contracts) * len(approaches)
    print(f"[run] {len(contracts)} contracts x {len(approaches)} approach(es) = {total} tasks | "
          f"test-limit {args.test_limit} timeout {args.timeout}s | {len(done)} already recorded")
    i = 0
    for approach in approaches:
        for c in contracts:
            i += 1
            if (approach, c["id"]) in done:
                continue
            t0 = time.time()
            rec = run_contract(c, approach, pg, args.test_limit, args.timeout)
            append(rec)
            print(f"[{i}/{total}] {approach:6} {c['cls']:16} {c['id'][:38]:38} -> "
                  f"{rec['verdict']:12} {round(time.time()-t0,1)}s", flush=True)
    summarize()


if __name__ == "__main__":
    main()
