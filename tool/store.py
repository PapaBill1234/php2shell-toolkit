#!/usr/bin/env python3
"""store.py - tiny sqlite persistence for jobs, leads, harvest cache."""
import json
import os
import sqlite3
import threading
import time

DB = os.environ.get("P2S_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "p2s.db"))
LOCK = threading.Lock()


def _c():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init():
    with LOCK, _c() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS jobs(
          id TEXT PRIMARY KEY, url TEXT, host TEXT, state TEXT, reason TEXT,
          probe TEXT, harvested TEXT, created REAL, updated REAL);
        CREATE TABLE IF NOT EXISTS leads(
          host TEXT, page TEXT, param TEXT, score INT, why TEXT, url TEXT,
          created REAL, PRIMARY KEY(host, page, param));
        CREATE TABLE IF NOT EXISTS harvest(
          host TEXT PRIMARY KEY, data TEXT, created REAL);
        """)


def add_job(jid, url, host):
    with LOCK, _c() as c:
        c.execute("INSERT OR REPLACE INTO jobs(id,url,host,state,reason,created,updated)"
                  " VALUES(?,?,?,?,?,?,?)", (jid, url, host, "queued", "", time.time(), time.time()))


def upd(jid, **kw):
    kw["updated"] = time.time()
    sets = ", ".join("%s=?" % k for k in kw)
    with LOCK, _c() as c:
        c.execute("UPDATE jobs SET %s WHERE id=?" % sets, list(kw.values()) + [jid])


def jobs(limit=300):
    with LOCK, _c() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM jobs ORDER BY created DESC LIMIT ?", (limit,))]


def queued():
    with LOCK, _c() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM jobs WHERE state='queued' ORDER BY created")]


def pending_count():
    with LOCK, _c() as c:
        r = c.execute("SELECT COUNT(*) n FROM jobs WHERE state IN ('queued','running')").fetchone()
        return r["n"]


def add_lead(host, page, param, score, why, url):
    with LOCK, _c() as c:
        c.execute("INSERT OR REPLACE INTO leads(host,page,param,score,why,url,created)"
                  " VALUES(?,?,?,?,?,?,?)",
                  (host, page, param, score, json.dumps(why), url, time.time()))


def leads():
    with LOCK, _c() as c:
        return [dict(r) for r in c.execute("SELECT * FROM leads ORDER BY score DESC, created DESC")]


def harvest_get(host, ttl=86400):
    with LOCK, _c() as c:
        r = c.execute("SELECT data,created FROM harvest WHERE host=?", (host,)).fetchone()
        if r and time.time() - r["created"] < ttl:
            return json.loads(r["data"])
    return None


def harvest_put(host, data):
    with LOCK, _c() as c:
        c.execute("INSERT OR REPLACE INTO harvest(host,data,created) VALUES(?,?,?)",
                  (host, json.dumps(data), time.time()))


def export_md():
    out = ["# php2shell leads", ""]
    for l in leads():
        out.append("- **%s** `%s?%s` score=%s — %s" % (l["host"], l["page"], l["param"],
                                                        l["score"], l["why"]))
    return "\n".join(out) + "\n"
