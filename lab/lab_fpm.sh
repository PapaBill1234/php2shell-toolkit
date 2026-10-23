#!/bin/bash
# Known-good local lab: PHP 8.4.4-fpm + nginx over TLS (streaming works over
# HTTPS in Chrome). Target: https://127.0.0.1:19443/lfi.php (reader /raw.php)
set -u
if ! docker ps --format '{{.Names}}' | grep -qx php2shell-lab; then
  docker rm -f php2shell-lab >/dev/null 2>&1
  docker run -d --name php2shell-lab -p 127.0.0.1:19268:80 -p 127.0.0.1:19443:443 \
    p2s-lab:ready sleep infinity >/dev/null
  sleep 1
fi
docker exec php2shell-lab bash -c 'pgrep -x php-fpm >/dev/null || php-fpm -D; pgrep -x nginx >/dev/null || nginx'
docker exec php2shell-lab bash -c 'printf %s "<?php echo @file_get_contents(\$_GET[\"f\"]);" > /var/www/html/raw.php'
docker cp /tmp/php2shell-up/lab/index.php php2shell-lab:/var/www/html/lfi.php 2>/dev/null
for i in $(seq 1 30); do
  curl -sk -o /dev/null -m 2 https://127.0.0.1:19443/lfi.php && break
  sleep 0.3
done
echo "lab ready: https://127.0.0.1:19443/lfi.php (reader: /raw.php?f=)"
