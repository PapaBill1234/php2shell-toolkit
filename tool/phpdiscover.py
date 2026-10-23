#!/usr/bin/env python3
"""phpdiscover.py - find a PHP endpoint on hosts whose front page is an SPA.

A soft-404 SPA answers 200 for `/index.php` with the same shell as `/`, so a
plain status check lies. This probes a curated path list and only accepts a
candidate when the server behaves like PHP for it:

  * `X-Powered-By: PHP`, or a `Set-Cookie: PHPSESSID` on a progress POST
    (proving upload_progress is on), or
  * a body that differs from the `/` shell and carries PHP artefacts.

Usage: python3 phpdiscover.py https://host [--json]
"""
import json
import socket
import ssl
import sys
from urllib.parse import urlparse

BND = "----p2sDisc"
PATHS = [
    "/index.php", "/api.php", "/admin.php", "/wp-login.php", "/login.php",
    "/user/loginform", "/install.php", "/phpinfo.php", "/info.php",
    "/test.php", "/api/index.php", "/admin/index.php", "/v1/index.php",
    "/public/index.php", "/app.php", "/home.php", "/demo.php", "/docs.php",
    "/status.php", "/health.php", "/version.php", "/xmlrpc.php",
    "/config.php", "/check.php", "/ping.php", "/up.php", "/go.php",
    "/s.php", "/r.php", "/main.php", "/portal.php", "/site.php",
]
SPA_HINTS = ("__NEXT_DATA__", "id=\"__next\"", "id=\"root\"", "id=\"app\"",
             "window.__NUXT__", "data-reactroot")


def req(origin, path, post=False, timeout=12):
    u = urlparse(origin)
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    body = b""
    head = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n" % (path, host)
    if post:
        body = ("--%s\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nx\r\n"
                "--%s\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nA\r\n"
                "--%s--\r\n" % (BND, BND, BND)).encode()
        head += ("Content-Type: multipart/form-data; boundary=%s\r\n"
                 "Content-Length: %d\r\n" % (BND, len(body)))
    head += "\r\n"
    raw = socket.create_connection((host, port), timeout=timeout)
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = ctx.wrap_socket(raw, server_hostname=host)
    try:
        raw.sendall(head.encode() + body)
        data = b""
        while len(data) < 262144:
            c = raw.recv(65536)
            if not c:
                break
            data += c
        return data
    finally:
        raw.close()


def split(resp):
    head, _, body = resp.partition(b"\r\n\r\n")
    try:
        code = int(head.split(b" ")[1])
    except (IndexError, ValueError):
        code = 0
    return code, head.lower(), body


def check(origin, path):
    try:
        code, head, body = split(req(origin, path))
    except OSError:
        return False, "conn"
    if code in (0, 404, 410):
        return False, str(code)
    if b"x-powered-by: php" in head:
        return True, "php-header"
    try:
        pcode, phead, _pb = split(req(origin, path, post=True))
    except OSError:
        return False, str(code)
    if b"phpsessid" in phead and b"set-cookie" in phead:
        return True, "progress-cookie"
    txt = body.decode("latin1", "replace")
    if code in (401, 403):
        return False, "denied"
    if any(h in txt for h in SPA_HINTS) and len(body) > 2000:
        return False, "spa"
    if any(h in txt.lower() for h in ("php version", "session.upload_progress", "<b>warning</b>", "<b>fatal error</b>")):
        return True, "php-artefact"
    return False, "shell"


def find(origin):
    hits = []
    for path in PATHS:
        ok, why = check(origin, path)
        if ok:
            hits.append({"path": path, "why": why})
    return hits


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    origin = sys.argv[1].rstrip("/")
    hits = find(origin)
    if "--json" in sys.argv:
        print(json.dumps({"origin": origin, "php": hits}))
    else:
        print("%s: %d php endpoint(s)" % (origin, len(hits)))
        for h in hits:
            print("  %-22s %s" % (h["path"], h["why"]))
    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
