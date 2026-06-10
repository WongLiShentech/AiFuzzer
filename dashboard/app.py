#!/usr/bin/env python3
"""Web dashboard (deliverable #4).

Lets a user submit a contract and view its vulnerability report, plus the
random-vs-AI-guided comparison from the benchmark. Thin Flask layer over the
aifuzz package — it calls the same `analyze()` the CLI uses.

Status: scaffold (Milestone M4). Routes and template are in place; the analyze
route returns the report once the engines land (M2/M3).
"""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, render_template, request

# aifuzz is importable because the package is installed (pip install -e .)
from aifuzz.analyzer import analyze

app = Flask(__name__)
RESULTS = Path(__file__).resolve().parents[1] / "results"


@app.route("/")
def index():
    has_results = RESULTS.exists() and any(RESULTS.glob("*.json"))
    return render_template("index.html", has_results=has_results)


@app.route("/analyze", methods=["POST"])
def analyze_route():
    contract = request.form.get("contract", "")
    mode = request.form.get("mode", "random")
    try:
        report = analyze(contract, mode=mode)
        return {"ok": True, "report": report.to_dict()}
    except FileNotFoundError as e:
        return {"ok": False, "error": str(e)}, 404
    except NotImplementedError as e:
        # Honest: engines are M2/M3.
        return {"ok": False, "error": f"engine pending: {e}"}, 501


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")),
            debug=os.getenv("FLASK_DEBUG") == "1")
