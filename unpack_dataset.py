"""Reconstruct the .sol corpus from the published Hugging Face dataset.

The corpus is published as Parquet, not as loose .sol files -- Hugging Face limits a directory to
10,000 files and clean/ holds 11,058. The fuzzer, however, compiles real files, so a working
checkout needs the sources written back to disk.

Each row carries its original path in `file_name` and its full text in `source_code`, so the tree
this writes is byte-identical to the corpus the published results were measured on, including the
provenance header and the DATASET_SPLIT stamp the benchmark reads.

    huggingface-cli login          # the dataset repo is private
    python unpack_dataset.py --out ~/smart-contracts

or, if the parquet files were copied across by hand:

    python unpack_dataset.py --out ~/smart-contracts --from-dir /media/usb/data

Then point the tool at it:

    export DATASET_DIR=~/smart-contracts
    export RAG_CORPUS_DIR=~/smart-contracts
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = "Ai-Fuzz/smart-contracts"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="directory to write the corpus into")
    ap.add_argument("--repo", default=REPO)
    ap.add_argument("--splits", default="reference,test")
    ap.add_argument("--from-dir", default=None,
                    help="read data/<split>.parquet from here instead of downloading")
    args = ap.parse_args()

    try:
        import pandas as pd
        from huggingface_hub import hf_hub_download
    except ImportError as e:
        print(f"missing dependency: {e}\n  pip install pandas pyarrow huggingface_hub")
        return 1

    out = Path(args.out).expanduser()
    out.mkdir(parents=True, exist_ok=True)

    total = 0
    for split in args.splits.split(","):
        split = split.strip()
        if args.from_dir:
            f = Path(args.from_dir).expanduser() / f"{split}.parquet"
            if not f.exists():
                f = Path(args.from_dir).expanduser() / "data" / f"{split}.parquet"
            if not f.exists():
                print(f"  not found: {split}.parquet under {args.from_dir}")
                return 1
            print(f"[{split}] reading {f}", flush=True)
        else:
            print(f"[{split}] downloading...", flush=True)
            try:
                f = hf_hub_download(args.repo, f"data/{split}.parquet", repo_type="dataset")
            except Exception as e:
                if "401" in str(e) or "Repository Not Found" in str(e):
                    print(f"  {args.repo} is private and this machine is not authenticated.\n"
                          f"  run:  huggingface-cli login\n"
                          f"  or pass --from-dir if you copied the parquet files across.")
                    return 1
                raise
        df = pd.read_parquet(f)
        print(f"[{split}] {len(df)} contracts -> {out}", flush=True)
        for i, r in enumerate(df.itertuples(index=False), 1):
            p = out / r.file_name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(r.source_code, encoding="utf-8")
            if i % 2000 == 0:
                print(f"  ...{i}/{len(df)}", flush=True)
        total += len(df)

    # The benchmark reads the split from a stamp inside each file, so verify it survived rather
    # than assuming: a mismatch here means every later count is wrong.
    import re
    seen = {"reference": 0, "test": 0}
    vuln = 0
    for p in out.rglob("*.sol"):
        head = p.read_text(encoding="utf-8", errors="replace")[:900]
        m = re.search(r"DATASET_SPLIT:\s*(\w+)", head)
        if m and m.group(1) in seen:
            seen[m.group(1)] += 1
        if re.search(r"GROUND_TRUTH_LABEL:\s*1", head):
            vuln += 1
    print(f"\n  wrote {total} contracts")
    print(f"  split stamps on disk: reference={seen['reference']}  test={seen['test']}")
    print(f"  vulnerable: {vuln}")
    print(f"\n  export DATASET_DIR={out}")
    print(f"  export RAG_CORPUS_DIR={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
