# PHP2Shell — Detection & Mitigation Guide

PHP `session.upload_progress` OOM Use-After-Free Remote Code Execution

**CVE-2026-109618 / CVE-2026-109619**

## Vulnerability Summary

| | |
|---|---|
| Type | Use-After-Free (CWE-416) |
| Severity | CVSS v4.0 9.2 (Critical) |
| Auth | None |
| Affected SAPI | All SAPIs serving web requests: Apache mod_php, PHP-FPM, php-cgi, FrankenPHP, LiteSpeed (highest risk: mod_php) |
| Affected Versions | PHP 5.4.0 ~ 8.5.11 (all branches below the fixed release, see below) |
| Fixed Versions | PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (released 2026-10-21) |

OOM during multipart parsing triggers `longjmp` before `zend_activate_modules()`, leaving `PS(id)` and `PS(http_session_vars)` dangling. The skipped `RSHUTDOWN` lets the pointers survive into the next request, enabling Use-After-Free leading to remote code execution.

### Affected Versions

| Branch | Affected | Fixed In | Support Status |
|---|---|---|---|
| PHP 8.6 (pre-release) | 8.6.0 RC1 ~ RC3 | 8.6.0 RC4 | Pre-release |
| PHP 8.5 | 8.5.0 ~ 8.5.11 | **8.5.12** | Active |
| PHP 8.4 | 8.4.0 ~ 8.4.26 | **8.4.27** | Active |
| PHP 8.3 | 8.3.0 ~ 8.3.35 | **8.3.36** | Security only |
| PHP 8.2 | 8.2.0 ~ 8.2.34 | **8.2.35** | Security only (EOL 2026-12-31) |
| PHP 7.4 ~ 8.1 | All releases | No official release — minimal source backports from the PHP security team | EOL |
| PHP 5.4 ~ 7.3 | All releases | No fix | EOL |

- The vulnerable `session.upload_progress` code path has existed since **PHP 5.4.0**, when the feature was introduced.
- Linux distributions (Debian, Ubuntu, RHEL, AlmaLinux, etc.) often backport fixes without changing the upstream version string. Determine status from the vendor security advisory (USN / DSA / RHSA / ALSA) package version, not `php -v`.
- Official Docker `php` images follow upstream versions; rebuild and redeploy from a fixed tag (e.g. `php:8.4.27-apache`).
- The exploit chain in this repository was verified in a lab against PHP 8.3 ~ 8.5 (default target: 8.4.26).

## Detection Rules

### Snort 2

```
alert tcp any any -> any $HTTP_PORTS ( \
    msg:"purplehound: PHP session upload progress field in multipart POST (CVE-2026-109618, CVE-2026-109619)"; \
    flow:established,to_server; \
    content:"POST"; http_method; \
    content:"multipart/form-data"; http_header; nocase; \
    content:"PHP_SESSION_UPLOAD_PROGRESS"; http_client_body; fast_pattern; \
    pcre:"/(?i:content-disposition)[ \t]*:(?:[^\r\n]|\r?\n[ \t])*?\;\s*(?i:name)\s*=\s*(?:\x22PHP_SESSION_UPLOAD_PROGRESS\x22|PHP_SESSION_UPLOAD_PROGRESS(?=[\;\s]))/P"; \
    reference:cve,2026-109618; \
    reference:cve,2026-109619; \
    classtype:web-application-attack; \
    sid:1499040051; rev:1; \
)
```

### Suricata

```
alert http any any -> any any ( \
    msg:"purplehound: PHP session upload progress field in multipart POST (CVE-2026-109618, CVE-2026-109619)"; \
    flow:established,to_server; \
    http.method; content:"POST"; \
    http.content_type; content:"multipart/form-data"; nocase; \
    http.request_body; content:"PHP_SESSION_UPLOAD_PROGRESS"; fast_pattern; \
    pcre:"/(?i:content-disposition)[ \t]*:(?:[^\r\n]|\r?\n[ \t])*?\;\s*(?i:name)\s*=\s*(?:\x22PHP_SESSION_UPLOAD_PROGRESS\x22|PHP_SESSION_UPLOAD_PROGRESS(?=[\;\s]))/"; \
    reference:cve,2026-109618; \
    reference:cve,2026-109619; \
    classtype:web-application-attack; \
    sid:1499040052; rev:1; \
)
```

### Detection Logic

The rules above match traffic satisfying all of the following conditions:

1. `POST` method
2. `Content-Type: multipart/form-data` header
3. Request body contains the `PHP_SESSION_UPLOAD_PROGRESS` field name

`PHP_SESSION_UPLOAD_PROGRESS` is a reserved field name that triggers PHP session upload progress tracking. Legitimate web applications rarely send this field directly, so matching traffic can be classified as a malicious attempt with high confidence.

## Mitigation

> **Updating is the only complete fix.** Per the official PHP advisory, the workarounds below reduce exposure to specific attack paths but do not make an installation safe. Switching SAPI (e.g. mod_php → PHP-FPM) is **not** a mitigation: PHP-FPM is also affected.

### 1. Upgrade PHP (Recommended)

Upgrade to **PHP 8.5.12, 8.4.27, 8.3.36 or 8.2.35** (or later). For PHP 8.1 and older, upgrade to a supported branch or apply a vendor/LTS backport.

### 2. Disable session.upload_progress (CVE-2026-109619)

Apply in `php.ini`, an FPM pool, or server configuration that takes effect **before request parsing**. Do not rely on `ini_set()` or FPM `.user.ini`.

```ini
; php.ini
session.upload_progress.enabled = 0
```

```apache
# Apache mod_php
php_admin_flag session.upload_progress.enabled off
```

```ini
; PHP-FPM pool (e.g. /etc/php/8.x/fpm/pool.d/www.conf)
php_admin_flag[session.upload_progress.enabled] = off
```

### 3. Disable fatal_error_backtraces on PHP 8.5 (CVE-2026-109619)

```ini
; php.ini (PHP 8.5 only)
fatal_error_backtraces = 0
```

### 4. Set memory_limit = -1 (CVE-2026-109618)

Removes the OOM bailout that leaves request state partially initialized. Set it so applications cannot override it (e.g. `php_admin_value`).

```ini
; php.ini
memory_limit = -1
```

```apache
# Apache mod_php
php_admin_value memory_limit -1
```

```ini
; PHP-FPM pool
php_admin_value[memory_limit] = -1
```

- Do **not** substitute `RLIMIT_AS` / `RLIMIT_DATA`; these can cause the vulnerable allocation failure.
- A container or cgroup memory limit can serve as an availability boundary, but it is not a complete mitigation.

### 5. Lower post_max_size / upload_max_filesize (CVE-2026-109618)

Use `post_max_size = 8M` for applications without file uploads, or `32M` if uploads are required. Keep `upload_max_filesize` below `post_max_size`.

```ini
; php.ini
post_max_size = 8M
upload_max_filesize = 2M
```

### 6. Deploy WAF Rules

Block requests containing the `PHP_SESSION_UPLOAD_PROGRESS` field using a WAF such as ModSecurity.

```
# ModSecurity
SecRule REQUEST_BODY "PHP_SESSION_UPLOAD_PROGRESS" \
    "id:2026109618, \
     phase:2, \
     deny, \
     status:403, \
     msg:'PHP session upload progress exploit attempt (CVE-2026-109618)'"
```

### Mitigation Priority

| Priority | Action | Effect |
|---|---|---|
| **Immediate** | Upgrade PHP | Root cause fix |
| **Immediate** | Deploy IDS/IPS rules | Detect and block exploit attempts |
| **High** | `session.upload_progress.enabled = 0` (+ `fatal_error_backtraces = 0` on 8.5) | Reduces CVE-2026-109619 exposure |
| **High** | `memory_limit = -1` | Reduces CVE-2026-109618 exposure |
| **Medium** | Lower `post_max_size` / `upload_max_filesize` | Additional hardening |

> **Based on this repository's exploit (`exploit.py`) only:** switching to PHP-FPM or running multiple prefork workers prevents *this* exploit chain from landing, but neither is a mitigation for the vulnerability. Per the official advisory, PHP-FPM and all other web SAPIs remain affected.

## Verification Tools

This repository includes tools for verifying vulnerability status before and after applying patches. **Use only in isolated lab environments.**

| File | Description |
|---|---|
| `exploit.py` | Vulnerability verification (auto brute-force r0 + RCE) |
| `Docker/` | Vulnerable target environment (php:8.4.26-apache) |

### Verification Environment Setup

```bash
cd Docker
docker compose up -d --build
```

### exploit.py

```bash
# File-based oracle (writes output to webroot, reads it back)
python3 exploit.py --host 127.0.0.1 --port 8088 \
    --cmd 'id>/var/www/html/pwn.txt' --fetch /pwn.txt

# Blind timing oracle (no webroot write required)
python3 exploit.py --host 127.0.0.1 --port 8088 --sleep-oracle
```

Options: `--zif-offset`, `--dtor-offset`, `--r0-lo`, `--r0-hi`, `--r0-lowbits`, `--thorough`

### Attack Profile

| | |
|---|---|
| Vector | OOM corruption → stale `EG()` |
| Pre-Auth | Yes |
| Conditions | None — any endpoint |
| SAPI | mod_php |

The exploit requires no authentication, no valid application endpoint, and no application-specific precondition. The chain runs entirely in PHP's request-parsing layer, which executes before any application code. A single unauthenticated POST to **any** URL on the host is sufficient. As a result, **every server running mod_php is attackable unconditionally**, regardless of the application, routing, or login state. WordPress, Laravel, a static error page, or a bare `index.php` are all equally exposed.

### Exploitation Constraints

> The constraints below apply to **this repository's exploit (`exploit.py`)**, not to the vulnerability itself. Environments that do not meet them are still vulnerable and must be patched.

- **SAPI**: This exploit targets mod_php or lsphp. On PHP-FPM the worker is respawned on OOM, so this chain does not land — PHP-FPM is still affected per the official advisory.
- **Worker count**: This exploit requires a single prefork worker for deterministic heap grooming.
- **`session.upload_progress.enabled`**: Must be `On` (default in most distributions).
- **Offsets**: Build-specific (`--zif-offset`, `--dtor-offset`). Defaults target php:8.4.26-apache.
- **`r0_offset`**: Runtime heap layout value, not in the binary. `exploit.py` brute-forces it automatically.

## Disclaimer

This tool is provided for authorized security research and educational purposes only. Use only in isolated lab environments with explicit authorization.
