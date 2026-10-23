# php2shell toolkit — research release

Tooling for **CVE-2026-109618 / CVE-2026-109619** (`session.upload_progress`
use-after-free, plus the session-injection logic bug). It is a research tool: a
dashboard, a CLI, a lab harness and the write-ups of what does and does not work.

The vulnerability is **patched upstream** (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35,
and 8.6.0-rc4). Everything here is for research and authorised testing.

## Legal notice

**Use this only on systems you own or have explicit, written permission to
test.** Running any part of this toolkit - probing, scanning, crawling, or
either exploit chain - against a system you do not own or have not been
authorised to test is **illegal in most countries**. Unauthorised access to,
or interference with, a computer system is a criminal offence under laws such
as the Computer Fraud and Abuse Act (United States), the Computer Misuse Act
(United Kingdom) and comparable legislation elsewhere, and it can lead to
prosecution, heavy fines and **prison sentences**. It is also a civil wrong:
the owner can sue you for the damage, downtime and remediation costs.

Using a proxy, VPN, hosting provider or shared infrastructure does not make
this lawful, and it does not hide you: a scan does not become legal because it
was pointed at an IP rather than a domain, or because someone else published
the target list.

This is not legal advice. If you are not certain you have permission, you do
not have it: stop and obtain it in writing first.

## What this is, and what it is not

**The exploits are ports, not new research.** Chain A follows Bulletdev's
`php2shell-poc`; the UAF chain and its spray/leak/oracle design are
78ResearchLab's `PHP2Shell-Full-Chain-Exploit`. Both are credited in `NOTICE`.

**What was added is the operating layer** - the parts that decide whether a
stranger's host can be reached at all and whether a run survives contact with
reality:

| added here | why |
|---|---|
| `offsets.py` + `farm.py` + `offsets.json` | offsets are derived from a build by signature instead of hand-edited per version; five builds already farmed |
| `matrix.py` + per-version labs | coverage is measured, not claimed |
| capability gating (8.3-8.5 only, fixed releases skipped) | no 400 s spent on a build that cannot work |
| `chaina.py` | 18 save-path candidates, quote escaping, marker then a real `id` check - their script has one default path and no execution proof |
| `phpdiscover.py` | 32 paths, behavioural PHP proof, SPA-shell rejection; both references assume you know a PHP page |
| LFI scanning, harvesting, crawling | both references assume you know the parameter |
| one CLI and a dashboard (batch, plain statuses, leads export) | theirs are two unrelated scripts with no orchestration |
| Cloudflare handling (in-browser solve, optional solver, proxy forwarder) | theirs assume an unobstructed localhost connection |
| real-host hardening (probe timeouts, browser-tab starvation, port/env overrides, chromium fallback, optional tools) | each was an observed wedge or crash |

**Where it stands:** chain A verified on 5.6.40 / 7.4.33 / 8.3.2 / 8.4.4 and the
full chain on 8.3.35 / 8.4.26 / 8.5.11 (24-47 s). The full chain does **not**
work on <= 8.2 - no leak on those branches, deliberately out of scope - so chain
A is the documented route there.

**When to use theirs instead:** a one-off reproduction on their own lab. Their
`exploit.py --host --port` is shorter and needs no dashboard. Use this one when
you are pointing at many unfamiliar hosts, need version-specific offsets, or
want discovery and batch reporting.

## Layout

```
tool/      the actual toolkit: p2s CLI, dashboard, both chains, discovery,
           offset farm, matrix runner, session/crawl helpers
lab/       local labs (php-fpm and apache+mod_php) and the kill-receipt runner
docs/      WEAPON_NOTES.md (everything learned, including dead ends),
           ROOT_CAUSE.md (the memory bug, line by line)
research/  one-off probes kept because they document how each finding was made
reference/ two third-party repos this was checked against (see NOTICE)
```

## Credentials

Nothing is bundled - bring your own:

* `SOLVERCF_KEY` - only for the optional Cloudflare solver path
  (`export SOLVERCF_KEY=...`, get one at <https://solvercf.com>). The code ships
  the literal placeholder `YOUR_SOLVERCF_KEY` and refuses to run without a real
  value.
* Proxy - pass it inline for the solver/`p2s`, format `host:port:user:pass`
  (`p2s --proxy ...`); for `proxy_local.py` set `UPSTREAM`, `UP_USER`, `UP_PASS`.

## Requirements

* Python 3.10+ — the CLI and both chains are stdlib-only, so nothing to install
  for them
* Dashboard only: `pip install -r requirements.txt` and a Chrome/Chromium
  binary in `PATH`
* Optional: `ffuf`, `katana`, `gau` for crawling/harvest (missing ones are
  skipped, the scan just gets shallower)
* Docker only if you want the labs

Missing optional tools and a missing solver key never stop a run.

## First run: verify your setup

Two labs ship here. Start with the cheap one and stop when you see the expected
line - if that works, your environment is fine.

**Lab prerequisites:** Docker for `lab/lab_fpm.sh`. The Apache lab
(`lab/lab_apache.sh`) runs Apache on the *host*, so it needs `sudo`, `apache2`,
`libphp` and `setarch` installed and writes under `/tmp/php2shell_ap`.

```
bash lab/lab_fpm.sh                    # php 8.4.4-fpm + nginx, https://127.0.0.1:19443
./tool/p2s https://127.0.0.1:19443/lfi.php --chaina --param page
```

Expected final line:

```
SHELL uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

If you get that, probing, discovery, the session write and the include all work
on your machine. Then try the dashboard (see below) and finally a real target.

## Full chain lab

The UAF chain needs a single-worker prefork SAPI, so use the reference image
(shipped under `reference/PHP2Shell-Full-Chain-Exploit/Docker`, already mapped
to port 8088):

```
cd reference/PHP2Shell-Full-Chain-Exploit/Docker
sed -i 's/php:8.4.26-apache/php:8.3.35-apache/' Dockerfile   # or 8.5.11, or keep 8.4.26
docker compose up -d --build
cd ../../..
python3 tool/farm.py 8.3.35                                  # derive + store offsets
./tool/p2s http://127.0.0.1:8088/index.php --fullchain --build php-8.3.35-apache
```

Expected: `PROOF uid=33(www-data) ...` after 30-60 s of sweeping.

## Using the dashboard

```
python3 tool/dashboard.py          # http://127.0.0.1:8099
```

1. Paste one host or URL in the top box and press **Scan**. It probes the site,
   looks for PHP (including a behavioural check and a 32-path discovery pass),
   harvests history, crawls, and tries the `page`-style parameters it can derive.
   **Just probe** stops after the reachability/PHP stage.
2. Watch the console. Statuses are deliberately plain:
   `running` -> `blocked` (bot wall), `done no PHP`, `done no LFI parameter`,
   `lead LFI candidate: <param>?`, `timeout` (site did not answer), or
   `shell` with either the poisoned session path (**chain A**) or the full
   chain's result.
3. Real candidates land in **leads**. **Copy list** and **Export .md** give you
   the URLs to re-check by hand.
4. For volume use the **batch** box: one URL per line, **Scan all**. Two Chrome
   slots run in parallel; **Stop** clears the queue. Rows show host + status,
   never the payloads.
5. Override the parameter (`parameter` box, empty = auto), the command
   (`cmd`, default `id`), or run a later command in the **console** box with
   **Run** against the loaded target.

Notes: the dashboard binds localhost only; set `P2S_TOKEN` to require a token,
`P2S_PROXY` for an outbound proxy, `P2S_SOLVER=1` + `P2S_PROXY` to let it try
the solver, `P2S_PORT` if 8099 is taken. Chrome is launched headless by the tool
on two fixed ports.

## CLI reference

```
./tool/p2s <url> --probe                       # reachability + PHP only
./tool/p2s <url> --chaina --param page         # chain A, needs an LFI param
./tool/p2s <url> --chaina --param page --save-paths /var/lib/php/sessions
./tool/p2s <url> --fullchain --build php-8.4.26-apache   # needs the UAF chain's SAPI
python3 tool/phpdiscover.py https://host       # which .php paths exist at all
python3 tool/farm.py 8.3.35                    # add offsets for another build
python3 tool/matrix.py                         # re-run every lab, one row per build
```

`--chaina` prints `INCLUDE <session path>` then `SHELL <output>`; `no hit` means
none of the save paths answered. `--fullchain` prints the leak, the sweep and
either `PROOF` or `no r0 in the swept range`.

## Troubleshooting

| symptom | cause / fix |
|---|---|
| `no LFI parameter` | the page takes no include param, or it is hidden: widen the parameter wordlist, or point `--param` at one you know |
| `blocked` | bot wall. Re-run (self-solve often clears it), or set `P2S_SOLVER=1` with a working `P2S_PROXY`, or supply `P2S_CF_COOKIE` |
| `no hit` from chain A | wrong save path, or `cleanup=On` on the target (`Off` needed), or the include needs a suffix |
| `browser would not start` | no Chrome/Chromium in `PATH` |
| `port 8099 is busy` | `P2S_PORT=8098` |
| dashboard shows an import error | `pip install -r requirements.txt` |
| `set SOLVERCF_KEY first` | only for the solver path; get a key or leave `P2S_SOLVER` unset |
| crawler finds nothing | `ffuf` / `katana` / `gau` not installed; scans still run, just shallower |
| full chain `leak failed` | wrong build offsets, >1 worker, or PHP < 8.3 |

## Open gaps and shortcomings

Honest list — these are the reasons it is a research tool, not a product.

1. **≤ 8.2 has no leak, so the full chain stops there - deliberately out of
   scope.** The trigger OOMs identically, but every value PHP prints about the
   session is live on those branches: the `Set-Cookie` id, transparently
   rewritten URLs and the `SID` constant are all owned at the moment they are
   written, so nothing carries recycled memory. Checked and rejected: two
   PHPSESSID parts, strict mode, moved OOM, pages that echo the session,
   `use_trans_sid` rewriting. A leak would need a surviving alias read by a
   later output operation, i.e. new research of unknown length. Chain A covers
   those versions with an LFI, so that is the documented route instead of
   chasing this.
2. **The forge is not version-neutral.** `zif_system` / `zval_ptr_dtor` are
   derived, but the zval type tags and the `pDestructor` offset are hardcoded.
   A future 8.x layout change breaks it.
3. **Offsets need a local copy of the exact build.** The farm pulls official
   images; distro packages (Debian/Ubuntu/RHEL) differ and are only supported by
   deriving from the vendor package yourself. A stripped build with no
   `php_exec_ex` stub pair will not derive.
4. **The full chain needs a single-worker SAPI.** With FPM pools of >1 worker the
   dangling state and the sparse requests land on different workers and every
   stage becomes a lottery. Nothing auto-detects or works around that.
5. **No docroot knowledge** in the dashboard, so it uses the blind sleep oracle
   and cannot return command output; the CLI can if you pass `--fetch`.
6. **LFI discovery is weak.** 32 curated paths plus a parameter wordlist; it
   finds obvious `index.php?page=` cases and misses routed/CMS shapes.
   Hosts behind a bot wall are marked `blocked`, not worked around.
7. **The session save path is guessed** (18 common values). Custom paths fail
   silently as "no hit".
8. **Chain A needs `cleanup=Off`.** With the default `cleanup=On` the record is
   removed at request end and only a race include works; nothing does that race.
9. **No auth on the dashboard** and no concurrency control beyond two Chrome
   slots; a long batch can leave one wedged target until its socket timeout.
10. **Verified only on Apache prefork labs.** FPM/nginx, LiteSpeed, FrankenPHP
    and CGI are untested for the full chain (the FPM lab is used for chain A
    only). Our own Apache 8.3.2 lab also fails the leak while the official 8.3.35
    image works, so the trigger is still env-sensitive.
11. **The target list is not bundled** (`tool/targets.txt` is empty). Many
    AI-proxy sites are SPAs behind Cloudflare and end as `blocked` / `no PHP`,
    so any list you paste is a sample, not a promise.
12. **Bugs are known to exist** in the dashboard: the job timeout is checked
    after the probe rather than around it, and a crashed browser slot is not
    recovered mid-job.

## Support

**No support is given.** This is a research release published as-is: there is
no issue triage, no guaranteed response, no fixes and no help with running it
against your own targets. Nothing here is maintained, and any use is at your
own risk and under your own authorisation.

## Provenance

* `reference/php2shell-poc` — Bulletdev (chain A idea, `cleanup`/save-path
  requirements). No licence file in that repo at the time of copying.
* `reference/PHP2Shell-Full-Chain-Exploit` — 78ResearchLab, MIT. The chain in
  `tool/fullchain.py` is a port of it.
* `/proc`-based level reads, the forged-layout offsets and the
  `php_exec_ex`-stub offset derivation were worked out here.

No credentials are included. `tool/solvercf.py` ships the literal placeholder
`YOUR_SOLVERCF_KEY` and exits with a clear message until you export your own.
