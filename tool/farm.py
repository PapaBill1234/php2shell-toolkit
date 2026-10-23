#!/usr/bin/env python3
"""farm.py - build an offset entry for an official php image.

    python3 farm.py 8.4.26            # -> offsets.json: php-8.4.26-apache

Pulls the image, extracts libphp.so and derives zif_system / zval_ptr_dtor with
offsets.py. Distro builds are stripped and differ per release; run the farm for
whichever build the target runs instead of guessing.
"""
import json
import os
import subprocess
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    ver = sys.argv[1]
    tag = "php:%s-apache" % ver
    name = "farm-%s" % uuid.uuid4().hex[:6]
    subprocess.run(["docker", "pull", "-q", tag], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["docker", "create", "--name", name, tag], check=True, stdout=subprocess.DEVNULL)
    so = "/tmp/farm-%s.so" % ver
    try:
        subprocess.run(["docker", "cp", "%s:/usr/lib/apache2/modules/libphp.so" % name, so], check=True)
    finally:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL)
    out = subprocess.run([sys.executable, os.path.join(HERE, "offsets.py"), so],
                         capture_output=True, text=True).stdout
    vals = dict(line.split("=", 1) for line in out.strip().splitlines() if "=" in line)
    zif, dtor = vals.get("zif_system", ""), vals.get("zval_ptr_dtor", "")
    if not (zif.startswith("0x") and dtor.startswith("0x")):
        print("derive failed:\n" + out)
        return 1
    path = os.path.join(HERE, "offsets.json")
    db = json.load(open(path)) if os.path.exists(path) else {}
    db["php-%s-apache" % ver] = {"zif": zif, "dtor": dtor}
    json.dump(db, open(path, "w"), indent=1)
    print("php-%s-apache -> zif %s dtor %s" % (ver, zif, dtor))
    return 0


if __name__ == "__main__":
    sys.exit(main())
