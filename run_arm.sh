#!/bin/sh
cd "$(dirname "$0")"
arm="$1"
lock="eval_out/.lock_${arm}"
if [ -e "$lock" ]; then echo "LOCKED: $arm already running (pid $(cat $lock))"; exit 1; fi
echo $$ > "$lock"
trap 'rm -f "$lock"' EXIT
export PYTHONUTF8=1 BENCH_TEST_LIMIT=50000 BENCH_TIMEOUT=45
echo "=== START $arm $(date) ===" >> eval_out/PROGRESS.txt
python -u benchmark_testset.py --approach "$arm" > "eval_out/log_${arm}.txt" 2>&1
echo "=== DONE  $arm $(date) ===" >> eval_out/PROGRESS.txt
