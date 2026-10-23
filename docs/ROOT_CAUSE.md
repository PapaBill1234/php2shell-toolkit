# php2shell — corrected root cause (CVE-2026-109618 / CVE-2026-109619)

This supersedes the jackalsyn bundle mechanics. The bundle located the right
function but the wrong primitive: the two cached `post_bytes_processed`
zval* stay inside the live `progress->data` tree (update() does
`Z_TRY_ADDREF` before every `zend_hash_update`, session.c:3213), which is
why the bundle's own lab never fired ASAN. The two 9.2s are the two
serialize/unserialize **context globals** orphaned by a pre-RINIT bailout
in the same callback.

## The two bugs

`php_session_rfc1867_callback` runs inside `php_hash_environment`, BEFORE
`zend_activate_modules` and therefore BEFORE `PHP_RINIT_FUNCTION(basic)`
zeroes `BG(serialize)` / `BG(unserialize)` (basic_functions.c:393-395).

Both globals cache `{ level, data }` for the var layer:

- **Bug S (serialize context)** — `PS_SERIALIZER_ENCODE_FUNC(php)`
  (session.c:1079-1108) and `_php_serialize` (964-975) run
  `PHP_VAR_SERIALIZE_INIT ... PHP_VAR_SERIALIZE_DESTROY` with NO zend_try.
  A memory_limit bailout inside `php_var_serialize` (smart_str_erealloc on
  the growing tree) skips the destroy → `BG(serialize).level` stays 1,
  `.data` points at the orphaned `php_serialize_data`
  (HashTable{pDestructor=ZVAL_PTR_DTOR} + uint32 n at +0x38; 64-byte alloc).

- **Bug U (unserialize context)** — `php_session_decode` (session.c:274-288)
  wraps the serializer decode in `zend_try`; the `zend_catch` path runs
  `php_session_cancel_decode()` then **`zend_bailout()` without
  `PHP_VAR_UNSERIALIZE_DESTROY`** → `BG(unserialize).level` stays 1, `.data`
  points at the orphaned `php_unserialize_data`
  (8208 bytes = 3 pages: last/first_dtor/last_dtor ptrs + embedded
  `var_entries` with 1018 `zval*` slots).

The bailout skips basic RINIT (only `PG(modules_activated)` set at
main.c:1875 guards it), so nothing clears the globals.
`shutdown_memory_manager(0)` reclaims the context allocation while
`BG(*).data` still points at it. **Next request on the same process:**
`php_var_serialize_init` / `php_var_unserialize_init` see `level != 0`
(var.c:1349 / var_unserializer.re:63) and **reuse the freed block as the
live context** → UAF read/write through:

- `php_add_var_hash` (`data->n += 1`, hash walk for refs/objects) — Rina's
  ASAN: READ of 4 at freed+0x38 = exactly `php_serialize_data->n`.
- `tmp_var()` (var_unserializer.re:157-185): reads `last_dtor` (+16) and
  `used_slots` from the reclaimed block → `var_push_dtor` writes a copied
  zval to `last_dtor->data[used_slots]` on every decoded refcounted value →
  **arbitrary 16-byte write (value+type_info)**.
- `var_access()` (211-228): `R:n;` in the session payload resolves
  `entries.data[n]` from forged bytes → arbitrary `zval*` injected into the
  decoded tree as a reference → dtor at the next update's
  `zend_hash_update` replacement → `zval_ptr_dtor(attacker_address)` →
  forged `zend_object` → handlers → `zend_call_function(fci, fcc)` →
  `zif_system`.

## The chain (per CVE)

1. **Arm request** (unauth multipart, sid chosen via PHPSESSID form field
   or cookie): `min_freq` window (default 1 s stall, or slow drip at
   origin) → multiple `update()` rounds; each round's decode+encode grows
   the session tree (filename bytes are attacker-controlled and land in
   `current_file["name"]`); with victim `memory_limit` small relative to
   `post_max_size` (8M-class configs vs 8M body of names) the pre-RINIT
   decode (Bug U) or encode (Bug S) exceeds the limit → bailout → context
   orphaned, `sess_<sid>` file keeps the last-written tree (Bug S) or is
   destroyed (Bug U's cancel_decode).
2. **Process survival gate**: mod_php prefork survives startup FAILURE
   (sapi_apache2.c:671 bailout → request dtor, child lives) — Calif demo
   SAPI. php -S survives (php_cli_server.c accept loop). FPM/CGI call
   `php_module_shutdown()` + exit on startup failure (fpm_main.c:1871,
   cgi_main.c:2464) — on those the arm request is worker-kill DoS unless
   the OOM lands post-startup. lsphp: unverified, test empirically.
3. **Fire request** (same child): early multipart form parts allocate
   attacker strings that reclaim the freed context block
   (Bug S: 64-byte bin → ≤39-byte values; Bug U: 3-page large alloc →
   ~8.2KB values), THEN the file part triggers the first pre-RINIT
   `update()` whose INIT reuses the forged context.
   - Bug U forge: `first/last_dtor` → arbitrary zval write / `var_access`
     → arbitrary `zval_ptr_dtor` → object → `zend_call_function`.
   - Bug S forge: fake HashTable `pDestructor` (needs leaked
     `zval_ptr_dtor` — the Flatt banner value) → `zend_hash_destroy`
     calls it per forged bucket.

`session.upload_progress.enabled=0` closes both (session.c:3239).

## Why the bundle failed and grok stalled

- Bundle: reclaimed the *decoded duplicate tree* bins (320) — but the
  cached zval* never pointed there; ASAN never fired, `call=0` inert.
- Grok: correctly proved the trees stay alive, then concluded "no bug" —
  but his OOM tests landed on an Ubuntu-patched 8.1.2 encode path (destroy
  ran post-OOM) and on SAPIs that exit on startup failure; he never tested
  the `zend_catch` decode path (the swallow is unconditional in 8.4 and
  the same code exists in 8.1-8.5).
