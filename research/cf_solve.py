#!/usr/bin/env python3
"""Solve the Cloudflare managed challenge in our own headless Chrome and dump
cf_clearance + UA for reuse against the target."""
import json, sys, time, urllib.request, websocket

BASE = "http://127.0.0.1:9223"
URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8099"

def page_ws():
    for _ in range(20):
        data = json.load(urllib.request.urlopen(BASE + "/json/list"))
        for t in data:
            if t.get("type") == "page":
                return t["webSocketDebuggerUrl"]
        time.sleep(0.5)
    return None

ws_url = page_ws()
if not ws_url:
    print("no page target"); sys.exit(1)
ws = websocket.create_connection(ws_url, timeout=30)
mid = [0]
def cmd(method, params=None):
    mid[0] += 1
    ws.send(json.dumps({"id": mid[0], "method": method, "params": params or {}}))
    while True:
        m = json.loads(ws.recv())
        if m.get("id") == mid[0]:
            return m.get("result", m)

def ev(js):
    r = cmd("Runtime.evaluateutime" if False else "Runtime.evaluate", {"expression": js, "returnByValue": True})
    return r.get("result", {}).get("value")

cmd("Network.enable"); cmd("Page.enable")
REAL_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
cmd("Emulation.setUserAgentOverride", {"userAgent": REAL_UA, "acceptLanguage": "en-GB,en;q=0.9", "platform": "Linux x86_64"})
ev("Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")
cmd("Page.navigate", {"url": URL})
ua = ev("navigator.userAgent")
print("UA:", ua)
clearance = None
clicked = 0
for i in range(60):
    time.sleep(1)
    title = ev("document.title")
    cookies = cmd("Network.getCookies", {"urls": [URL]}).get("cookies", [])
    clearance = next((c["value"] for c in cookies if c["name"] == "cf_clearance"), None)
    if clearance:
        print("SOLVED after %ds title=%r" % (i + 1, title))
        break
    # try clicking the turnstile widget if visible
    rect = ev("(function(){var f=document.querySelector('iframe');if(!f)return null;var r=f.getBoundingClientRect();return [r.x+r.width/2,r.y+r.height/2,r.width,r.height]})()")
    if rect and clicked < 12 and i % 4 == 0:
        x, y = rect[0], rect[1]
        for t in ("mousePressed", "mouseReleased"):
            cmd("Input.dispatchMouseEvent", {"type": t, "x": x, "y": y, "button": "left", "clickCount": 1})
        clicked += 1
        print("click %d at %r title=%r" % (clicked, (x, y), title))
else:
    print("NOT SOLVED; title=%r" % ev("document.title"))

if clearance:
    print("CF_CLEARANCE=" + clearance)
    print("UA=" + (ua or ""))
else:
    sys.exit(2)
