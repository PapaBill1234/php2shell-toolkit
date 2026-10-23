#!/usr/bin/env python3
"""solvercf.py - Cloudflare challenge solving via SolverCF token API.

Modes:
  cookie  -> returns cf_clearance (+UA/client hints); needs a proxy
  token   -> returns a Turnstile token; inject in-browser

Usage:
  python3 solvercf.py <url> --mode cookie --proxy host:port:user:pass
  python3 solvercf.py <url> --mode token
"""
import argparse
import json
import re
import sys
import time
import urllib.request
import os

# publishable service key: override with SOLVERCF_KEY (rotate freely, it is shared with the release)
KEY = os.environ.get("SOLVERCF_KEY", "YOUR_SOLVERCF_KEY")   # placeholder, bring your own
BASE = "https://solvercf.com/token/extension/"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")


def post(path, payload, timeout=30):
    if KEY in ("", "YOUR_SOLVERCF_KEY") and "clientKey" in payload:
        raise SystemExit("set SOLVERCF_KEY (https://solvercf.com) - no key ships with this repo")
    import subprocess
    out = subprocess.run(["curl", "-s", "--max-time", str(timeout), "-X", "POST",
                          BASE + path, "-H", "Content-Type: application/json",
                          "-d", json.dumps(payload)], capture_output=True, text=True).stdout
    try:
        return json.loads(out or "{}")
    except ValueError:
        return {"raw": out[:200]}


def challenge_opts(url):
    """Pull sitekey/cData/chlPageData/cType out of the challenge page."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html"})
    try:
        html = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        html = e.read().decode("utf-8", "replace")
    m = re.search(r"window\._cf_chl_opt\s*=\s*\{(.*?)\};", html, re.S)
    if not m:
        return {}
    body = m.group(1)

    def g(k):
        mm = re.search(r"%s:\s*'([^']*)'" % k, body)
        return mm.group(1) if mm else None

    return {k: v for k, v in (("sitekey", g("sitekey")), ("cData", g("cData")),
                              ("chlPageData", g("chlPageData")), ("cType", g("cType")))
            if v}


def solve(url, mode="token", proxy=None, sitekey=None, action=None, attempts=2):
    for _ in range(attempts):
        opts = challenge_opts(url)
        key = sitekey or opts.get("sitekey")
        if not key:
            return {"ok": False, "error": "no sitekey (pass --sitekey)"}
        task = {
            "type": "TurnstileTask",
            "websiteUrl": url,
            "websiteKey": key,
            "cloudflareTaskType": mode,
            "pageAction": action or opts.get("cType") or "managed",
            "userAgent": UA,
        }
        if opts.get("cData"):
            task["data"] = opts["cData"]
        if opts.get("chlPageData"):
            task["pageData"] = opts["chlPageData"]
        if proxy:
            task["proxy"] = proxy
        try:
            r = post("createTask", {"clientKey": KEY, "task": task})
        except Exception as e:
            return {"ok": False, "error": "createTask: %s" % e}
        tid = r.get("taskId")
        if not tid:
            return {"ok": False, "error": str(r)[:160]}
        for _i in range(25):
            time.sleep(3)
            try:
                res = post("getTaskResult", {"clientKey": KEY, "taskId": tid})
            except Exception:
                continue
            st = res.get("status")
            if st == "ready":
                sol = res.get("solution") or {}
                if mode == "cookie" and sol.get("cookie"):
                    return {"ok": True, "mode": mode,
                            "cookie": sol["cookie"], "ua": sol.get("userAgent") or UA,
                            "ch": {"Sec-CH-UA": sol.get("secChUa") or "",
                                   "Sec-CH-UA-Mobile": sol.get("secChUaMobile") or "",
                                   "Sec-CH-UA-Platform": sol.get("secChUaPlatform") or ""}}
                if mode == "token" and sol.get("token"):
                    return {"ok": True, "mode": mode, "token": sol["token"]}
            if st in ("failed", "expired"):
                break
    return {"ok": False, "error": "no solution"}


def main():
    a = argparse.ArgumentParser()
    a.add_argument("url")
    a.add_argument("--mode", choices=["cookie", "token"], default="token")
    a.add_argument("--proxy")
    a.add_argument("--sitekey")
    a.add_argument("--action")
    ns = a.parse_args()
    if KEY in ("", "YOUR_SOLVERCF_KEY"):
        raise SystemExit("set SOLVERCF_KEY first (get one at https://solvercf.com) - "
                         "no key ships with this repo")
    print(json.dumps(solve(ns.url, ns.mode, ns.proxy, ns.sitekey, ns.action), indent=2))


if __name__ == "__main__":
    main()
