#!/bin/bash
export RAG_CORPUS_DIR="C:/smart-contracts"
cd /c/AI-Fuzzing-Framework
echo "=== $(date '+%F %T') starting B1-CoT (finishing clean set) ==="
python -u benchmark_testset.py --approach ai-seed-cot >> eval_out/run_cot_full.log 2>&1
echo "=== $(date '+%F %T') B1-CoT done, starting B1 (ai-seed) ==="
python -u benchmark_testset.py --approach ai-seed >> eval_out/run_b1.log 2>&1
echo "=== $(date '+%F %T') ALL DONE ==="
