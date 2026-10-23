#!/usr/bin/env python3
"""discover.py - crawl (katana) + content discovery (ffuf) for a host.

Feeds the scanner with real paths on PHP-ish hosts. Runs server-side (these
tools don't pass bot challenges by themselves, so browser crawl stays the
primary on Cloudflare hosts; this augments it elsewhere).

Returns {"paths": [...], "params": [...], "dirs": [...]}
"""
import os
import re
import subprocess
import tempfile
from urllib.parse import urlparse, parse_qs

GO = "/tmp/go/bin/"
WL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist.txt")

def _run(cmd, timeout):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={**__import__("os").environ, "PATH": GO + ":" + __import__("os").environ.get("PATH", "")})
        return r.stdout.splitlines()
    except Exception:
        return []


def crawl(host, base="/"):
    out = _run([GO + "katana", "-u", "https://%s%s" % (host, base), "-d", "2",
                "-jc", "-silent", "-timeout", "6", "-c", "8"], 70)
    urls = []
    for u in out:
        try:
            p = urlparse(u.strip())
        except Exception:
            continue
        if p.netloc.split(":")[0].lower() not in (host.lower(), "www." + host.lower()):
            continue
        if p.path and p.path != "/":
            urls.append(p.path)
    return urls


def dirs(host):
    out = _run([GO + "ffuf", "-u", "https://%s/FUZZ" % host, "-w", WL,
                "-mc", "200,204,301,302,401,403", "-t", "25", "-s", "-timeout", "6"], 90)
    hits = []
    for line in out:
        m = line.strip().split()
        if m and not m[0].startswith("{"):
            path = m[0]
            if not path.startswith("/"):
                path = "/" + path.split("https://", 1)[-1].split("/", 1)[-1]
            hits.append(path)
    return hits


def discover(host, base="/"):
    paths, params = [], set()
    for p in crawl(host, base):
        if p not in paths:
            paths.append(p)
    for p in dirs(host):
        if p not in paths:
            paths.append(p)
    for p in list(paths):
        for k in parse_qs(urlparse(p).query).keys():
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,30}", k):
                params.add(k)
    phpish = [p for p in paths if p.endswith(".php")][:8]
    return {"paths": paths[:25], "php": phpish, "params": sorted(params)[:25]}
