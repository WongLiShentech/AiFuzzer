#!/usr/bin/env python3
"""
generate_labels.py — regenerate labels.csv from contract metadata blocks.

Walks every .sol file under this dataset/ directory, parses the metadata
comment block that each contract carries, and writes labels.csv.

Design notes (project principles: modular / extensible / flexible):
  * No folder names, vulnerability types, or tool/Solidity versions are
    hardcoded. New subfolders and new contracts are picked up automatically
    on the next run with zero code changes.
  * Ground truth is read from the GROUND_TRUTH_LABEL field inside each
    contract, so the CSV can never drift from the contracts themselves.

Usage:
    python generate_labels.py
"""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

# Resolve paths relative to this file so the script works from any CWD.
DATASET_DIR = Path(__file__).resolve().parent
OUTPUT_CSV = DATASET_DIR / "labels.csv"

CSV_COLUMNS = [
    "filename",
    "relative_path",
    "vulnerability_type",
    "label",
    "source_repo",
    "eea_section",
]

# Matches "  * FIELD_NAME: value" lines inside the leading /* ... */ block.
FIELD_RE = re.compile(r"^\s*\*?\s*([A-Z0-9_]+)\s*:\s*(.*?)\s*$")


def parse_metadata(text: str) -> dict[str, str]:
    """Extract KEY: value pairs from the first /* ... */ comment block."""
    start = text.find("/*")
    end = text.find("*/", start + 2) if start != -1 else -1
    if start == -1 or end == -1:
        return {}
    block = text[start + 2 : end]
    fields: dict[str, str] = {}
    for line in block.splitlines():
        m = FIELD_RE.match(line)
        if m:
            key, value = m.group(1), m.group(2)
            # Only keep the known metadata keys (ignore @source etc.).
            if key.isupper() and "_" in key or key in {
                "DATASET_SOURCE",
                "VULNERABILITY_TYPE",
                "GROUND_TRUTH_LABEL",
                "ACADEMIC_BASIS",
                "ORIGINAL_LICENSE",
            }:
                fields[key] = value
    return fields


def derive_source_repo(dataset_source: str) -> str:
    """Turn a full GitHub blob URL into an 'owner/repo' identifier."""
    m = re.search(r"github\.com/([^/]+/[^/]+)", dataset_source)
    if m:
        return m.group(1)
    return dataset_source or "unknown"


def collect_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for sol_path in sorted(DATASET_DIR.rglob("*.sol")):
        text = sol_path.read_text(encoding="utf-8", errors="replace")
        meta = parse_metadata(text)
        if "GROUND_TRUTH_LABEL" not in meta:
            print(f"  ! WARNING: no metadata block in {sol_path.name}, skipping")
            continue
        rel = sol_path.relative_to(DATASET_DIR).as_posix()
        rows.append(
            {
                "filename": sol_path.name,
                "relative_path": rel,
                "vulnerability_type": meta.get("VULNERABILITY_TYPE", "unknown"),
                "label": meta.get("GROUND_TRUTH_LABEL", ""),
                "source_repo": derive_source_repo(meta.get("DATASET_SOURCE", "")),
                "eea_section": meta.get("EEA_ETHTRUST_V3_SECTION", ""),
            }
        )
    return rows


def write_csv(rows: list[dict[str, str]]) -> None:
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def print_summary(rows: list[dict[str, str]]) -> None:
    total = len(rows)
    vulnerable = sum(1 for r in rows if r["label"] == "1")
    clean = sum(1 for r in rows if r["label"] == "0")
    print("\n=== Dataset label summary ===")
    print(f"  Contracts indexed : {total}")
    print(f"  Vulnerable (1)    : {vulnerable}")
    print(f"  Clean (0)         : {clean}")

    by_type: dict[str, int] = {}
    for r in rows:
        by_type[r["vulnerability_type"]] = by_type.get(r["vulnerability_type"], 0) + 1
    print("  By vulnerability type:")
    for vtype, count in sorted(by_type.items()):
        print(f"    - {vtype}: {count}")
    print(f"\n  Wrote {OUTPUT_CSV.relative_to(DATASET_DIR.parent)}")


def main() -> int:
    rows = collect_rows()
    if not rows:
        print("No labelled contracts found under", DATASET_DIR)
        return 1
    write_csv(rows)
    print_summary(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
