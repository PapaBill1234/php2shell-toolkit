#!/usr/bin/env python3
"""harvest.py - collect URLs/params for a host from public archives (gau).

Used by the dashboard batch pipeline: harvested .php URLs become crawler
seeds, harvested parameter names become discovery words. Archive APIs are
not Cloudflare'd, so this runs server-side; the actual scanning happens in
the browser.

CLI: harvest.py <host> [--max 200]
"""
import re
import subprocess
import sys
from urllib.parse import urlparse, parse_qs

GAU_BINS = ["/tmp/go/bin/gau", "gau"]


def _gau(host, limit=200):
    for b in GAU_BINS:
        try:
            r = subprocess.run([b, "--threads", "4", "--subs", host],
                               capture_output=True, text=True, timeout=30)
            if r.stdout:
                return r.stdout.splitlines()[:limit]
        except Exception:
            continue
    return []


def harvest(host, limit=200):
    h = host.split(":")[0]
    if h in ("localhost", "127.0.0.1") or h.replace(".", "").isdigit():
        return {"paths": [], "params": []}
    urls, params = [], set()
    seen = set()
    for u in _gau(host, limit):
        u = u.strip()
        if not u.startswith("http") or u in seen:
            continue
        seen.add(u)
        p = urlparse(u)
        if p.netloc.split(":")[0].lower() not in (host.lower(), "www." + host.lower()):
            continue
        if p.path.endswith(".php") and len(urls) < 8:
            urls.append(p.path)
        for k in parse_qs(p.query).keys():
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,30}", k):
                params.add(k)
    return {"paths": urls[:8], "params": sorted(params)[:25]}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit
    host = sys.argv[1].split("://")[-1].split("/")[0]
    print(harvest(host))
