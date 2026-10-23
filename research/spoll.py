#!/usr/bin/env python3
"""spoll.py <pid> <ms> - sample serialize data/flag during a request."""
import subprocess
import sys
import time

BG = 0x7FFFF6B70980
pid = sys.argv[1]
ms = int(sys.argv[2])
end = time.time() + ms / 1000.0
seen = []


def rd(off, n):
    out = subprocess.run(["sudo", "dd", "if=/proc/%s/mem" % pid, "bs=1",
                          "skip=%d" % off, "count=%d" % n,
                          "iflag=skip_bytes,count_bytes"], capture_output=True).stdout
    return out if len(out) == n else None


while time.time() < end:
    data = rd(BG + 0x348, 8)
    flag = rd(BG + 0x350, 4)
    if data and flag:
        row = (int.from_bytes(data, "little"), int.from_bytes(flag, "little"))
        if not seen or seen[-1] != row:
            seen.append(row)
    time.sleep(0.05)

for d, f in seen:
    print("serdata=%#x serflag=%d" % (d, f))
