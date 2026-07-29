#!/usr/bin/env python3
"""Web dashboard (deliverable #4) — the product surface for aifuzz.

Pages:
  /        landing page: what the tool does, who it's for, how it works.
  /app     the scanner: an ANALYZE view (product) and an EVALUATION view.

ANALYZE (product) is a unified batch scanner fed by three sources — uploaded
files (one or many), a Git repository, or the bundled example library — each
contract getting its own VULNERABLE/CLEAN report with the offending code and the
exploit sequence. EVALUATION runs the labeled suite (verdict vs ground truth) and
surfaces the random-vs-AI-guided comparison from results/benchmark.json.

Honest scope (pre-M3): fuzzing needs an oracle, so only contracts that carry
their own echidna_* properties (harnesses) produce findings; a raw contract is
reported as "needs a harness", which the M3 AI will generate automatically.
AI-guided mode therefore reports pending until M3.

Run inside the Docker image (it needs Echidna + git):
    docker compose run --rm --service-ports --no-deps aifuzz python dashboard/app.py
then open http://localhost:5000
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from flask import Flask, jsonify, render_template, request

from aifuzz.analyzer import analyze
from aifuzz.suite import load_cases, run_suite

app = Flask(__name__)
REPO = Path(__file__).resolve().parents[1]
REGISTRY = REPO / "harnesses" / "registry.yaml"
RESULTS = REPO / "results"

SCAN_BATCH = int(os.getenv("AIFUZZ_SCAN_BATCH", "25"))   # .sol files fuzzed per request; the UI paginates through the rest
GIT_CLONE_TIMEOUT = 120     # seconds


def _cases() -> list[dict]:
    return load_cases(str(REGISTRY))


def _read_source(path_str: str | None) -> dict | None:
    if not path_str:
        return None
    p = REPO / path_str
    try:
        if p.is_file():
            return {"path": path_str, "code": p.read_text(encoding="utf-8", errors="replace")}
    except OSError:
        pass
    return None


def _vulnerable_code(path_str: str | None) -> dict | None:
    """The actual offending lines, from the dataset's own <report> markers."""
    src = _read_source(path_str)
    if not src:
        return None
    lines = src["code"].splitlines()
    vuln: set[int] = set()
    for i, ln in enumerate(lines, start=1):
        if "<report>" in ln:
            for k in range(i + 1, len(lines) + 1):
                s = lines[k - 1].strip()
                if s and not s.startswith("//"):
                    vuln.add(k)
                    break
    if not vuln:
        return None
    wanted: set[int] = set()
    for n in vuln:
        for k in range(n - 2, n + 3):
            if 1 <= k <= len(lines):
                wanted.add(k)
    rows = [{"n": k, "code": lines[k - 1], "vuln": k in vuln} for k in sorted(wanted)]
    return {"path": src["path"], "lines": sorted(vuln), "rows": rows}


def _verdict(report) -> str:
    return "vulnerable" if len(report.findings) >= 1 else "clean"


def _analyze_one(contract_path: str, *, mode: str = "random", name: str = "",
                 contract: str | None = None, config: str | None = None,
                 target_for_code: str | None = None) -> dict:
    """Run one contract through the engine and return a result row. Never raises:
    compile errors / missing oracle become a 'skipped' status with a reason."""
    label = name or os.path.basename(contract_path)
    try:
        # auto=True: raw contracts get a Tier-2 harness synthesized from their shape
        # (same as the upload path) instead of being skipped for lacking an oracle.
        # mode is passed through: "ai-guided" routes to the RAG + Qwen path instead.
        report = analyze(contract_path, mode=mode, contract=contract, config=config, auto=True)
    except RuntimeError as e:
        return {"name": label, "status": "skipped", "reason": _sanitize(str(e))}
    except FileNotFoundError as e:
        return {"name": label, "status": "skipped", "reason": str(e)}
    return {
        "name": label,
        "status": _verdict(report),
        "report": report.to_dict(),
        "sources": None,                       # callers attach sources if available
        "vulnerable_code": _vulnerable_code(target_for_code),
    }


def _sanitize(msg: str) -> str:
    """Shorten engine errors and strip anything token-like from a message."""
    msg = re.sub(r"(https?://)[^@\s/]+@", r"\1***@", msg)  # redact creds in URLs
    first = msg.strip().splitlines()[0] if msg.strip() else "could not analyze"
    return first[:240]


# ---- pages ----------------------------------------------------------------

@app.route("/")
def landing():
    return render_template("landing.html", cases=_cases())


@app.route("/app")
def app_view():
    # Evaluation is a developer/research surface (it needs labeled ground truth,
    # which end users scanning their own contracts don't have). Shown in dev,
    # hidden in a customer build with AIFUZZ_DEV=0.
    dev = os.getenv("AIFUZZ_DEV", "1") == "1"
    return render_template("index.html", cases=_cases(), dev=dev)


@app.route("/api/cases")
def api_cases():
    return jsonify(_cases())


# ---- ANALYZE (product) ----------------------------------------------------

@app.route("/api/fuzz", methods=["POST"])
def api_fuzz():
    """Analyze one example case (by name) -> verdict + sources + vulnerable code."""
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("case")
    mode = data.get("mode", "random")
    cases = {c["name"]: c for c in _cases()}
    if name not in cases:
        return jsonify({"ok": False, "error": f"unknown case: {name!r}"}), 404
    case = cases[name]
    try:
        report = analyze(case["harness"], contract=case.get("contract"), config=case.get("config"))
    except (FileNotFoundError, RuntimeError) as e:
        return jsonify({"ok": False, "error": _sanitize(str(e))}), 400
    return jsonify({
        "ok": True, "verdict": _verdict(report), "report": report.to_dict(),
        "sources": {"harness": _read_source(case.get("harness")), "target": _read_source(case.get("target"))},
        "vulnerable_code": _vulnerable_code(case.get("target")),
    })


@app.route("/api/case-source", methods=["POST"])
def api_case_source():
    """Return a library case's source so the UI can show the code before fuzzing.
    Shows the real dataset contract; falls back to the harness for the two
    self-contained cases (oracle model + clean counter) whose target isn't a file."""
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("case")
    cases = {c["name"]: c for c in _cases()}
    if name not in cases:
        return jsonify({"ok": False, "error": f"unknown case: {name!r}"}), 404
    case = cases[name]
    target = _read_source(case.get("target"))
    harness = _read_source(case.get("harness"))
    return jsonify({"ok": True, "name": name, "vuln_type": case.get("vuln_type"),
                    "expect": case.get("expect"), "code": target or harness, "harness": harness})


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Analyze an uploaded/pasted contract. M2: must be self-contained with its
    own echidna_* oracle; auto-harnessing a raw contract is the M3 step."""
    data = request.get_json(force=True, silent=True) or {}
    source = data.get("source", "")
    name = (data.get("name") or "Uploaded.sol").strip()
    contract = data.get("contract") or None
    mode = data.get("mode", "random")
    if not source.strip():
        return jsonify({"ok": False, "error": "no contract source provided"}), 400
    with tempfile.TemporaryDirectory(prefix="aifuzz-upload-") as d:
        f = Path(d) / (name if name.endswith(".sol") else "Uploaded.sol")
        f.write_text(source, encoding="utf-8")
        try:
            # auto=True: if the upload has no echidna_* oracle, Tier-2 synthesis
            # tries to build a harness from its shape (no AI) before giving up.
            report = analyze(str(f), mode=mode, contract=contract, auto=True)
        except (FileNotFoundError, RuntimeError) as e:
            return jsonify({"ok": False, "skipped": True, "error": _sanitize(str(e))}), 200
    # The generated harness (attacker + oracle) is what Echidna actually ran and what a
    # finding's call sequence refers to -- show THAT, not the uploaded contract, whenever one
    # was synthesized. Previously this always echoed back `source`, so the "Test harness" panel
    # silently showed the user's own upload instead of the attack code (caught via a live demo:
    # an access-control finding's attack_val_N / force_fund wrappers were invisible).
    harness = ({"path": f"{report.harness_name}.sol", "code": report.harness_src}
               if report.harness_src else {"path": name, "code": source})
    return jsonify({
        "ok": True, "name": name, "verdict": _verdict(report), "report": report.to_dict(),
        "sources": {"harness": harness, "target": {"path": name, "code": source}},
        "vulnerable_code": None,
    })


@app.route("/api/scan-git", methods=["POST"])
def api_scan_git():
    """Clone a Git repo, find its .sol files, and fuzz each one. Full-stack but
    honest: contracts without an echidna_* oracle (or that need external deps to
    compile) are reported as 'skipped — needs a harness (M3)'."""
    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("repo_url") or "").strip()
    branch = (data.get("branch") or "").strip()
    token = (data.get("token") or "").strip()
    # Honour the fuzzing-mode toggle. The scan used to hardcode random regardless of what the
    # UI showed as selected, so "AI-guided" was a lie on this panel -- a repo scan and an
    # upload of the same file ran different arms while claiming to run the same one.
    mode = data.get("mode") or "random"
    if mode not in ("random", "ai-seed", "ai-guided"):
        mode = "random"
    try:
        offset = max(0, int(data.get("offset", 0)))   # which batch to scan (UI paginates)
    except (TypeError, ValueError):
        offset = 0
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return jsonify({"ok": False, "error": "Provide a valid http(s) Git URL."}), 400
    if shutil.which("git") is None:
        return jsonify({"ok": False, "error": "git is not available in the image."}), 500

    clone_url = url
    if token:  # embed token transiently for private repos; never echoed back
        clone_url = urlunparse(parsed._replace(netloc=f"{token}@{parsed.netloc}"))

    with tempfile.TemporaryDirectory(prefix="aifuzz-git-") as d:
        cmd = ["git", "clone", "--depth", "1", "--single-branch"]
        if branch:
            cmd += ["--branch", branch]
        cmd += [clone_url, d]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=GIT_CLONE_TIMEOUT)
        except subprocess.TimeoutExpired:
            return jsonify({"ok": False, "error": "git clone timed out."}), 504
        if proc.returncode != 0:
            return jsonify({"ok": False, "error": "git clone failed: " + _sanitize(proc.stderr)}), 400

        sols = sorted(p for p in Path(d).rglob("*.sol"))
        total = len(sols)
        batch = sols[offset:offset + SCAN_BATCH]        # this page only
        results = []
        for sol in batch:
            rel = str(sol.relative_to(d))
            res = _analyze_one(str(sol), mode=mode, name=rel)
            if res.get("report"):
                res["sources"] = {"harness": {"path": rel, "code": sol.read_text(encoding="utf-8", errors="replace")}, "target": None}
            results.append(res)
        next_offset = offset + len(batch)
        has_more = next_offset < total

    return jsonify({"ok": True, "found": total, "offset": offset, "scanned": len(results),
                    "mode": mode,          # echoed back so the UI can prove which arm ran
                    "has_more": has_more, "next_offset": next_offset if has_more else None,
                    "results": results})


# ---- EVALUATION (benchmark) ----------------------------------------------

@app.route("/api/suite", methods=["POST"])
def api_suite():
    results = run_suite(str(REGISTRY))
    return jsonify({"ok": True, "results": [
        {"name": r.name, "vuln_type": r.vuln_type, "expect": r.expect,
         "findings": r.findings, "passed": r.passed, "detail": r.detail, "error": r.error}
        for r in results
    ]})


@app.route("/api/benchmark")
def api_benchmark():
    f = RESULTS / "benchmark.json"
    if not f.is_file():
        return jsonify({"ok": True, "available": False})
    try:
        return jsonify({"ok": True, "available": True, "data": json.loads(f.read_text(encoding="utf-8"))})
    except (OSError, json.JSONDecodeError) as e:
        return jsonify({"ok": False, "error": str(e)}), 500


if __name__ == "__main__":
    # threaded=True: without it the dev server handles one request at a time, so a slow
    # AI-mode fuzz blocks every other click (including a fast Random request from a second
    # tab) until it finishes -- reproduced directly: a 27s Random request queued behind a
    # long AI-authored-harness call and timed out client-side waiting for its turn.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")),
            debug=os.getenv("FLASK_DEBUG") == "1", threaded=True)
