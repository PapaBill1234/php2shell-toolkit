# php2shell — lab receipts + weapon completion path

Lab: WSL Ubuntu 22.04, PHP 8.1.2-1ubuntu2.27, Apache 2.4.52 prefork +
mod_php (the Calif demo SAPI class) and php -S. All receipts below are from
live runs (gdb breakpoints on php_var_{,un}serialize_{init,destroy} printing
BG level/data, strace on openat/flock, error.log fatals).

## PROVEN (receipts in hand)

1. ARM (unauth multipart, pre-RINIT): 20x262144-byte filenames ->
   `Allowed memory size exhausted ... in Unknown on line 0` (pre-userland),
   HTTP 500, **process survives** (php -S accept loop AND Apache prefork
   child), session file keeps the attacker tree (1,049,473 B observed).
2. **Orphan caught in gdb**: 4 complete UNSER_INIT/UNSER_DESTROY pairs, then
   `UNSER_INIT level=0 data=(nil)` with NO destroy after it — the decode
   bailout swallowed by php_session_decode's zend_catch leaves
   `BG(unserialize) = {level=1, data=0x7ffff4ff4000}` (freed 12288-byte
   block) across requests. On other runs the same happens serialize-side:
   `SER_INIT level=1 data=0x7ffff4e67140` — **the fire request's session
   encodes run through the freed serialize context** (multiple reuse lines).
3. Bailout-leaked state cluster (all live-observed): locked sess fd (flock
   self-deadlock via stale PS(id) flush — strace: two fds on the same sess
   file, second flock ERESTARTSYS), PS(session_status)=active (Apache
   warning "Session ini settings cannot be changed when a session is
   active"), dangling PS(http_session_vars) tree re-encoded by the next
   request's rinit flush.
4. Which side OOMs is budget-dependent: the update-path encode peak
   (decoded tree + smart_str) structurally exceeds the decode peak, so
   encode-side orphaning dominates; decode-side arms via the END-cleanup
   decode or a pressure request (p1) tuned into the window
   decode_total < remaining < encode_peak.
5. Fire mechanics proven: mixed requests survive to userland with $_POST
   reflection intact; spray strings allocate pre-RINIT before the first
   update's context reuse; prefork child affinity requires fire retries
   (Calif 1/8).

## The two RCE chains (per CVE)

- Bug U (unserialize context, the RCE class): fire request's first decode
  reuses the freed php_unserialize_data. `tmp_var()` reads last_dtor(+16)
  and used_slots from attacker-reclaimed bytes -> var_push_dtor writes
  copied zvals to an arbitrary address (arbitrary 16-byte write);
  `var_access()` resolves R:n markers from forged entries.data[] ->
  arbitrary zval* injected as a reference into the decoded tree ->
  zval_ptr_dtor on the next update's zend_hash_update replacement ->
  forged zend_object -> handlers -> zend_call_function(fci,fcc forged in
  the same spray) -> zif_system. ASLR gate: one leaked heap/zval_ptr_dtor
  (the Flatt banner values = exactly this stage).
- Bug S (serialize context, the crash/leak class): fire's encode reuses the
  freed 64-byte php_serialize_data; fake HT pDestructor (attacker bytes at
  string val[24]) fires from zend_hash_destroy when the level returns to 1;
  the flush-encode of the dangling $_SESSION walks reference-looking
  reclaimed zvals (zval_spray pattern) into php_add_var_hash's hash walk
  with arData fully attacker-planted.

## Remaining steps to the final receipt (mechanical)

1. Land the U-side arm deterministically: arm tuned so all update cycles
   fit and the MULTIPART_EVENT_END cleanup decode (full tree decode, then
   near-empty encode) is the step that crosses memory_limit. Sweep
   --arm-namelen 96k..160k on the victim-equivalent build.
2. On the armed child, sweep fire spray 250..600 (fresh prefork child each
   attempt or Apache MaxRequestWorkers=1 for deterministic affinity).
3. Receipt targets, in order: SIGSEGV in php_var_unserialize with
   last_dtor deref (marker 0x4141...); Apache error.log "child pid N exit
   signal Segmentation fault"; then swap marker for the leaked address and
   walk tmp_var's write onto a live zval -> object -> zend_call_function.
4. Live box (lsphp 8.2.34 behind CF): SAPI survival unknown — if lsphp
   exits on startup failure like FPM, the arm is worker-kill DoS and the
   full chain needs the post-startup variant (userland-triggered OOM
   leaving level=1 in a live worker; RSHUTDOWN's zend_try path keeps the
   child). Test empirically with one arm request + follow-up GET.

## Victim requirements

memory_limit small relative to post_max_size (8M/8M class — Rina's box),
session.upload_progress.enabled=1 (stock), files save handler (stock),
persistent-per-child SAPI (mod_php prefork confirmed; lsphp TBD; FPM/CGI
= DoS-class only via the pre-RINIT path).


## KILL RECEIPT (2026-10-21 ~03:23-03:29 UTC, reproduced 2x)

Config: Apache 2.4.52 prefork mod_php 8.1.2, memory_limit=8M,
post_max_size=32M, min_freq=0, single child (apache -X / MaxRequestWorkers 1).
1. ARM: 1 file part, filename = 1,800,000 bytes -> 500, pre-RINIT OOM
   (alloc 1802240 = the name-string class), child survives, sess file 0 B
   (cleanup never reached), serialize/unserialize context orphaned.
2. FIRE: fast_fire.py burst. fire#0 (150x8.2KB zval-pattern spray + 600 t[]
   + 2 file parts) -> 200 survived. **fire#1 (250-spray) -> connection
   accepted, mod_authz granted 03:29:39, then SILENCE: no response, no
   error-log line, server 000 = child killed mid-php_hash_environment
   (crash with no handler = SIGSEGV class).** Reproduced twice (also
   03:23 run: fs=250 fire -> empty response, whole server dead).
The kill fires at the FIRST 250-class fire after a fresh arm (ASLR lottery
per attempt; video: "retry envelope attempts=8").

## Video intel (agent OCR of frames-calif/frames-kfir, 2026-10-21)

- Stage flow: `arming -> spraying -> leak -> call`; `LEAKED ::
  compact_natural_tables=149`; `compact table write :: phase=580/600
  bytes=4084`; `retry envelope :: attempts=8 timeout=25s`;
  `worker strategy :: adaptive`; chain id sid/boundary/marker format.
- Target profile: Ubuntu 26.04, PHP 8.5.4-1ubuntu1.4 (20251215), Apache
  2.4.46 prefork mod_php, glibc 2.39; `glibc heap grooming -> php85
  aligned495`; EXECUTED uid=33(www-data); elapsed 15.1-22.6s.
- Leak values drift per run: main_heap ~0x7b8fd5x00000, stale_reference
  +0x75c00, zval_ptr_dtor, zend_call_function (= dtor - 0xBE3F0 class).
- 288-byte spray forge: fields 0x40, 0x106 (IS_STRING_EX), 1, 1, 0x308
  (IS_OBJECT_EX); `system\x00` + command at +0xc8. 149x t[] parts.
- Weapon cmd: `python3 php2shell.py --profile 21 URL --command '...'`.
- CMS targets on video: WordPress 7.1.3, MediaWiki 1.46.2, Joomla 6.2.0,
  Laravel 13.36.0 (LARASHELL).

## 2026-10-22 - PHP 8.3.2 / Apache 2.4.58 prefork, ASLR off (/tmp/php2shell_ap)

Lab is the same config class as the kill receipt (MaxRequestWorkers 1,
memory_limit 8M, post_max_size 32M, min_freq 0) but on 8.3, not 8.1.2.

Measured, in order of discovery:

- Arm threshold: 12x98304-byte filenames = 200 (no OOM). 20x65536 = 500,
  pre-RINIT `Allowed memory size ... exhausted`, child survives, session tree
  written (1,183,xxx B). Use 20x65536 as the smallest working arm.
- **PS(save_path) is clobbered by the arm.** The next request resolves the
  session as `ndary=<boundary>/sess_<sid>` - a slice of the *previous*
  request's `Content-Type: multipart/form-data; boundary=...` - relative to
  the server cwd (Apache's cwd is `/` here). Symptom:
  `open(ndary=UctxPoc2026/sess_.., O_RDWR) failed: No such file or directory`,
  then `Failed to read session data` and an empty decode. Fix: create
  `/ndary=<boundary>` and copy the armed tree there (kill_apache.py does it).
  Consequence for real targets: the fire must not assume the arm's tree is
  reachable; a self-armed fire or a created directory is required.
- Pressure budget (4 KB parts, same sid so the tree is decoded): 200-956
  parts crash; >=960 OOM during multipart parsing (`tried to allocate 4096`)
  before the decode. Below 200 the request completes 200.
- Crash site (gdb, `handle SIGSEGV stop`): `rfc1867_post_handler ->
  php_session_flush -> php_session_reset_id -> session_adapt_url`. At the
  crash: `BG(serialize).level = 0`, `BG(unserialize).level = 0`,
  `BG(unserialize).data = NULL`, `BG(serialize).data = 0x7ffff60a0000`
  (dangling). So this receipt is the leaked session *flush/id* state, not a
  context reuse.
- Consequence for the marker stage: `php_var_unserialize_init` only skips the
  allocation when a level is non-zero (`0x2835c4` reads bg+0x340 and
  bg+0x360). Both are 0 at fire time, so a fresh `_emalloc_large(0x2018)` is
  installed at bg+0x358 and the decode writes into it - the 0x41 spray values
  are therefore *not* mutated yet, which matches the sweep (0 deviating `s[]`
  and `t[]` heads at n=20..200). The unser-context receipt needs an arm that
  leaves level=1 (OOM inside the decode), which neither the END-cleanup arm nor
  the flush-phase pressure request produces on 8.3.

Reproducibility of the kill: 4/4 and 3/3 via `python3 kill_apache.py`
(rounds default 3, pressure 950x4000). Receipt in
/tmp/php2shell_ap/error.log: `AH00051: child pid N exit signal Segmentation
fault (11)`.

### Why level=1 is not reachable from the END-cleanup arm (8.3)

memory_limit was swept byte-wise from 9,438,184 to 10,485,760 against the arm
(and again with `arm_mixed`, which adds 900 one-byte-named files to inflate the
decoded tree). Result: the arm *always* dies at the session-file read
(`tried to allocate 1,183,744`), never inside the decode; the transition to a
clean 200 is sharp (10,485,760 succeeds, 10,485,700 fails). The read buffer is
`file_size` bytes and the decode only re-reads the same bytes, so the read peak
>= decode peak and the decode can never be the allocation that crosses the
limit. `arm_mixed` therefore does not produce level=1 either; the tree still
decodes and `php_var_unserialize_destroy` runs.

Consequence: to leave BG(unserialize).level = 1 something other than the
END-cleanup decode has to OOM - the decode must be starved *after* the read,
e.g. a fire whose body pressure lands between the read and the end of the
decode (the 200-956 part band crashes earlier, in the flush), or a
post-startup userland OOM that keeps the worker.

## 2026-10-22 - decode-side orphan finally reached (8.3 / Apache, ASLR off)

State achieved and reproduced 3/3 (`go.py --nested 24000`), all in one live
worker that survives:

    alloc = 20480 (a decode arData chunk)
    resp  = 500 (bailout, worker alive)
    BG(unserialize) -> SER=0, UNSER=1, UNSERDATA=0x7ffff611d000 (live orphan)

So `php_var_unserialize_destroy` was skipped with the level up and a valid
context installed. Before this, every attempt died before the decode.

Three separate causes, each of which alone was enough to hide the decode:

1. **The arm leaves the session ACTIVE.** The next request's RINIT therefore
   skips initialize/read/decode entirely (`Session ini settings cannot be
   changed when a session is active`), and only re-encodes the dangling tree.
   That is why every fire so far reported level 0 and no spray mutation - the
   decode never ran, and the constant `tried to allocate 1183744` was the
   *encode* of the dangling 1.18 MB tree, not a file read.
2. **The arm leaves its session descriptor open (fd 10) with LOCK_EX.** The
   next request blocks in `ps_files_open()`'s blocking `flock` before it ever
   reads, so the worker wedges. Closing the stale fd via gdb releases it
   (flock is per open description, so the same process deadlocks itself).
3. **`PS(save_path)` is a dangling slice of the previous request's memory and
   it is not stable.** Observed values: `ndary=UctxPoc2026`, later
   `default output handler` (relative to cwd `/`). A payload written to a
   directory learned from one request can miss the next one, so the dir has to
   be re-learned per attempt from the `open(<dir>/sess_...)` line.

Recipe in `go.py`: arm 50x32768 names -> probe to learn the current stale dir
-> mkdir it -> close the stale fd -> place an amplifying session payload ->
send it. The payload is `k|<serialized>` (`php` handler needs the `key|`
prefix; a bare array decodes to nothing) and uses nested arrays: ~24k entries
= 709 KB of text but ~9 MB decoded (CLI-verified), so the decode, not the read,
crosses memory_limit. Lab config must stay at max_file_uploads 30000,
max_multipart_body_parts 40000, max_input_vars 40000.

`poll.py` samples the level from /proc/<pid>/mem, because gdb attaches
unreliably while the worker is bailing out, and gdb's python cannot write
/tmp files here (plain `printf` + a pipe works).

Still open: observe the reuse itself. A request after the bailout skips the
decode (cause 1), so it needs a page that closes the session and reopens with
a different id (`reopen2.php`); that still decodes nothing, and the session
file must be reachable at the per-request stale path, which is the next thing
to pin down. Then the marker stage.

## 2026-10-22 (cont.) - reuse receipt on the decode side, serialize-side mechanics

**Reuse is now observed**: after the amp leaves UNSER=1, a request that closes
the session and reopens under another id (`reopen5.php`, absolute save path)
reaches `php_var_unserialize` with `lvl=1 ptr=0x7ffff613b000` - the existing
context is used, no allocation. It 500s because the 709 KB payload blows the
reused context again, which is expected.

Serialize-side facts, from the disassembly rather than guesswork
(`php_var_serialize_init`, 0x273a22-0x273aa9):

- reuse happens only when `level == 0 && flag(+0x350) != 0`, and it sets
  `flag = level + 1`, i.e. 1 stays 1 - so a reuse is invisible in the flag.
- destroy clears both `data(+0x348)` and `flag` (observed 1 -> 0/0 in `spoll.py`).
- the arm leaves exactly that state (data 0x7ffff60a5000, flag 1) and the next
  request's flush reuses it.
- but the 64-byte block is re-occupied during the multipart parse before the
  flush, so the encode writes into whatever took it; poking our pattern into
  the block after the arm and then parsing does not survive either.
- offset bug fixed: serialize data is `bg+0x348` = 0x7ffff6b70cc8 (it had been
  read at 0x358, the unserialize pointer, which is why the ser state looked
  null for a while).

Next on this gap: identify which parse allocation takes the 64-byte block
(trace 64-byte emallocs, or watch the block content per part) and make that
allocation the attacker value, or forge the value so the encode survives it.

### Block content is untouched by the parse; a string cannot forge a valid array

Content probe: after the arm the 64-byte block at BG(serialize).data is free
and *not* reallocated during the multipart parse (a 0x5a pattern poked into it
is still intact at the crash). So the first flush reuses the block with
attacker bytes directly - no spray race is needed for the crash receipt.

Caught a live context at the store (0x273a6b, `$rbx`) in a healthy request:

    +0  refcount=1, +4 type_info=7 (IS_ARRAY)     <- zend_string gc when a string owns it
    +8  u.flags=8 (packed), +12 nTableMask=-2
    +16 arData=0x7ffff6a5f868, +24 nNumUsed=0 ...

So the block *is* a zend_array and `destroy` does `zend_hash_destroy(ptr)` +
`efree(ptr)`. When a 49-64 byte spray string reclaims it, the first 24 bytes
are the zend_string header (refcount/type/hash/len), i.e. gc/flags/nTableMask/
arData become garbage - the encode then dies in the hash walk. A string can
therefore deliver the crash but not a controlled write; a controlled ctx has to
arrive as decoded data. That is the fork in the road the call stage takes
(288-byte forged block instead of a 24-byte one).

### Context block is a zend_array - decoded-array reclaim, pDestructor offset

A decoded array explains the layout and gives a *surviving* reclaim. Payload
`k|a:4:{i:0;a:0:{}...}` decoded through the reopen page takes the dangling
64-byte block with a real empty array (56-byte zend_array -> 64 bin) and the
end-of-request encode completes: resp 200, block reads back
`01000000 07000000 08000000 feffffff 68f8a5f6ff7f0000 ...`.

Full measured layout (live context at the store, 64 bytes):

    +0  gc (refcount=1, type_info=7)   +8 u.flags=8 packed   +12 nTableMask=-2
    +16 arData   +24 nNumUsed   +28 nNumOfElements   +32 nTableSize
    +40 nInternalPointer   +48 nNextFreeElement   +56 pDestructor
    pDestructor reads 0x7ffff6906380 = zval_ptr_dtor.

Correction to the `fire_body` note: nNextFreeElement is +48 and pDestructor
+56, not +40/+48. Value bytes of a reclaiming string start at +24, so a string
can set pDestructor (val[32]) but not the header - the header it does write
(refcount/type/hash/len onto gc/flags/nTableMask/arData) is a string, not an
array, which is why a string reclaim always dies in the hash walk. An array
reclaim is valid but sets pDestructor itself; the next gap is getting a write
to +56 after the array is in place.

## 2026-10-23 - two reference repos read, chain A adopted, full chain ported

**Bulletdev/php2shell-poc** - Chain A is a pure logic exploit needing no memory
corruption: the progress handler stores the raw multipart `filename` in the
session and accepts `PHPSESSID` from the POST body, so a filename carrying PHP
code poisons `sess_<chosen id>`, and an LFI include of that file executes.
Requirements: `session.upload_progress.cleanup=Off` and a known save path
(`/var/lib/php/sessions`, `/tmp`, distro/cPanel variants). Quotes inside the
filename must be sent as `\"`; single quotes in the code avoid it. Verified on
our lab end to end (`INCLUDE ...` then `SHELL uid=33(www-data)`), implemented as
`chaina.py`, exposed as `p2s --chaina`, and wired into the dashboard after a
lead (state `shell`, verified through a real job).

**78ResearchLab/PHP2Shell-Full-Chain-Exploit** - the real UAF chain, and it
answers what we were re-deriving:

- trigger: pads + a file part + a 12 MB `big` field, memory 8M/post 64M, single
  prefork worker; OOM happens during parsing, before `zend_activate_modules()`,
  so `PS(id)` and `PS(http_session_vars)` dangle and RSHUTDOWN is skipped.
- **infoleak**: the next request (PHPSESSID part = `\x00`) returns raw heap
  memory; heap pointers in the body give the chunk base, and a pointer matching
  `zval_ptr_dtor - offset` gives the libphp base.
- spray 4071-byte values carrying a forged zend_reference at the r0 low bits
  and a forged zend_array payload at page+0x800; the fake array sets
  pDestructor to `zif_system` and arData to its own bucket, so the destroy fires
  `system(cmd)`.
- success oracle is fetch of a written file, or a blind sleep timing.
- reproduced on their lab: `PROOF uid=33(www-data)` in 36 s.

Ported verbatim as `fullchain.py`. New gap: **symbol offsets are per build**
(`zif_system` is not exported in distro builds; only `zval_ptr_dtor` is). The
reference hardcodes docker-php 8.4 offsets, so an offset farm (pull the official
image, compute both offsets from its libphp, key by version) is required before
the full chain can run against arbitrary targets.

### Offset derivation solved (`offsets.py`)

`zif_system` is a 10-byte stub `mov $n,%edx; jmp php_exec_ex` with n=1, and
`zif_passthru` is the same with n=3 on the *same* jump target, so the pair
identifies `php_exec_ex` users and n=1 is system. Validated: docker-php 8.4
yields exactly the reference values (zif 0x465370, dtor 0x65eb60); the Ubuntu
8.3 lab build yields zif 0x233a14, dtor 0x306380. docker-php images keep
`.symtab`, so there the symbol is used directly. The farm still needs per-target
modules (version banner -> pull matching image -> derive).

### Open: leak returns empty on our own lab

Running the ported chain against `/tmp/php2shell_ap` the leak request comes back
empty (len 0) while the worker stays alive (same pid, no exit-signal line). The
failing allocation is 2098791 - the request-body copy, i.e. the OOM lands before
any parsing. The same 12 MB trigger *without* the 1001-part prefix returns 200,
so the prefix is what moves the OOM into the parse. Next: bisect against the
reference lab (which works) on page body, part prefix count and ini, and check
whether `enable_post_data_reading`/body buffering differs.

### Offset farm + dashboard wiring (full chain usable)

`offsets.py` derives zif_system via the `mov $n,%edx; jmp php_exec_ex` stub pair
(n=1 system, n=3 passthru) and reads zval_ptr_dtor from .symtab. `farm.py` pulls
an official image, extracts libphp and stores both in `offsets.json`:

| build | zif | dtor |
|---|---|---|
| php-8.4.26-apache | 0x465370 | 0x65eb60 |
| php-8.5.11-apache | 0x5996e0 | 0x7b47a0 |
| php-8.3.35-apache | 0x3ac080 | 0x49ec50 |

`p2s --fullchain URL --build <entry>` runs the chain end to end; the dashboard
does it automatically after the probe when `X-Powered-By` matches a farm entry,
using the sleep oracle because a remote docroot is unknown. Verified through a
real job: state `shell`, "full chain (8.4.26)", 30 s.

Gotcha found: the probe's browser tab keeps the single worker's connection and
starves the chain; navigating the tab to `about:blank` before running fixes it.

Open on 8.3: our Ubuntu 8.3.2 lab never establishes the dangling `PS(id)`
(SIGSEGV/leak absent; cookie stays a clean generated id) even with the OOM
inside the parse (`tried to allocate 4096`). The 8.4 reference build does. Next:
compare `rfc1867` id handling 8.3 vs 8.4, or accept 8.4+ as the chain platform.

### 8.3 verdict for the full chain

`php_ps_globals` is `{save_path, session_name, id, ...}` (php_session.h), so `id`
is at PS+0x10 and `session_name` at +0x8. After a trigger that OOMs inside the
parse (`tried to allocate 4096`), with the session file provably created (the
file part is processed first), 8.3.2 still leaves `PS(id) = NULL` - the bailout
path nulls it - so the next request gets a freshly generated id (26 chars) and
the cookie leak never carries heap bytes. On 8.4.26 the same shape leaves it
dangling (reference lab: leak + `PROOF uid=33(www-data)`).

So: full chain = 8.4/8.5 builds (farm has 8.4.26 and 8.5.11); 8.3 falls back to
chain A. Revisit 8.3 only with the bailout/cleanup path in rfc1867 compared
against 8.4.

## 2026-10-23 - .php discovery + probe hardening

`phpdiscover.py` probes 32 PHP-ish paths and only accepts behavioural proof
(`X-Powered-By: PHP`, or a `Set-Cookie: PHPSESSID` on a progress POST, or PHP
artefacts in a body that is not the SPA shell). Wired into the job as the step
before a "no PHP" verdict; found paths are added as scan seeds and the negative
reason now states `no PHP (32 paths probed)` so it is visible that discovery ran.
Honest negative confirmed on a soft-404 host; a PHP host on `/` (behavioural
probe) and goes on to scanning.

Also hardened: the probe had no effective ceiling and one host wedged a worker
for minutes. CDP socket timeout 120 -> 45 s, CF wait 25 iterations, and a failed
setup now reports `site did not answer` (timeout) or `bot wall not passed`
(blocked) instead of hanging. Ten-host batch: 5 done/no PHP (discovery proven),
1 PHP-but-no-LFI, 2 blocked walls, 2 dead hosts.

### Version matrix for the full chain (measured, official images)

Built the reference Dockerfile against each official tag and ran the leak:

| build | leak | full chain |
|---|---|---|
| 8.3.35 | yes (chunk + libphp, 128 KB) | RCE 35.6 s |
| 8.4.26 | yes | RCE 24-36 s |
| 8.5.11 | yes | RCE 47.4 s |
| 8.2.34 | no (4 rotate/retry rounds) | not reachable |

So the chain is 8.3-8.5, matching the reference README. Our earlier 8.3.2
"verdict" was our hand-built lab, not the version. Fixed releases (8.2.35,
8.3.36, 8.4.27, 8.5.12) are gated out before a run; chain A still applies to
every vulnerable branch, 5.4 onwards, because the raw-filename write is that old.

### Boundary is 8.3, not 8.3.2-vs-8.3.35

Officially built 8.1.34 (leak no, farmed 0x36f470) and 8.2.34 (leak no) confirm
the chain needs 8.3+. Matrix (`matrix.py`, one row per local lab):

    8.5.11 RCE   8.4.26 RCE   8.3.35 RCE   8.2.34 miss   8.1.34 miss

Plan for the branches that miss, in order:

1. chain A covers them today - the raw-filename write exists since 5.4, so any
   vulnerable build with an LFI and cleanup=Off is exploitable without the leak;
2. diagnose the missing leak: compare the rfc1867 bailout between 8.2.34 and
   8.3.35 (the dangle is version-gated) and try (a) a trigger that OOMs after
   RINIT in userland so the skip lands differently, (b) leaking through
   PS(http_session_vars) instead of PS(id), (c) an echo channel other than the
   cookie (startup warnings include the session id);
3. make the forge version-neutral: derive the zval type tags (IS_REFERENCE,
   IS_OBJECT_EX) and the pDestructor offset from the target module by
   disassembly, like zif/dtor, instead of the hardcoded 0x30/0x38 and tag bytes.

### <8.3 leak diagnosis (8.1.34 / 8.2.34)

Trigger behaviour is identical to 8.3+ (same fatal, `tried to allocate 2098791`,
same 200), so the trigger is not the problem. Differences found:

- their leak request puts PHPSESSID after 1001 padding parts, but their ini has
  `max_input_vars = 1000`; the "Input variables exceeded" warning is printed
  before the session starts, so on 8.2 the Set-Cookie is suppressed entirely
  ("Session cookie cannot be sent after headers have already been sent").
  Moving PHPSESSID first and using 995 pads fixes the suppression; 8.3 was
  masking it because its id chunk gets recycled.
- with the cookie restored, 8.2 returns a clean 32-char generated id (chunk 0).
- reading `PS(id)` inside the worker after the trigger (ps_globals located via
  the `mov 0xbe393f(%rip)` slot at module+0xf2cbf0 for 8.2): the id is a *live*
  zend_string `"aaaaaaaaaaaaaaaaaaa"`, refcount 1 on both 8.2 and 8.3. The 8.3
  "leak" is that chunk being freed and reused by filler values within the leak
  request; on 8.2 the id stays owned, so the cookie never carries heap bytes.
- therefore <8.3 needs a different carrier. Best candidate is
  `PS(http_session_vars)` (the second dangling global from the CVE): after the
  OOM its array is freed, so a following request that encodes it walks freed
  memory. The target must echo the session (or we read the written file).

Chain A still covers 8.1/8.2 whenever an LFI exists.
