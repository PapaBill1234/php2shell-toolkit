#!/usr/bin/env python3
"""poll.py <pid> <ms> - sample BG(unserialize) from /proc/pid/mem (ASLR off)."""
import sys
import time

BASE = 0x7FFFF6600000
BG = BASE + 0x570980
pid = sys.argv[1]
ms = int(sys.argv[2])

try:
    fh = open("/proc/%s/mem" % pid, "rb", buffering=0)
except OSError as exc:
    print("open failed:", exc)
    sys.exit(1)


def rd(off, n=4):
    fh.seek(off)
    return fh.read(n)


end = time.time() + ms / 1000.0
seen = []
while time.time() < end:
    ser = int.from_bytes(rd(BG + 0x340), "little", signed=True)
    uns = int.from_bytes(rd(BG + 0x360), "little", signed=True)
    dptr = int.from_bytes(rd(BG + 0x358, 8), "little")
    row = (ser, uns, dptr)
    if not seen or seen[-1] != row:
        seen.append(row)
    if uns > 0:
        break
    time.sleep(0.05)

for ser, uns, dptr in seen:
    print("SER=%d UNSER=%d UNSERDATA=%#x" % (ser, uns, dptr))
