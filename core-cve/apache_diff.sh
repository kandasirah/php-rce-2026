#!/usr/bin/env bash
# Uji diferensial CVE-2026-109618 (OOM corruption) & CVE-2026-109619 (stale global state)
# antara PHP 8.4.11 (vulnerable, mod_php bawaan Kali) dan PHP 8.4.27 (patched).
#
# Dua instance Apache dijalankan lokal di 127.0.0.1:
#   :8091 -> mod_php 8.4.11  (vulnerable)
#   :8092 -> mod_php 8.4.27  (patched)
set -u

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN="$LAB_DIR/run"

# Modul mod_php untuk tiap sisi. Override lewat environment bila lokasi
# modul patched tidak persis seperti bawaan.
#   VULN_MOD=/path/libphp8.4.so  FIXED_MOD=/path/libphp8.4.so  ./apache_diff.sh start
VULN_MOD="${VULN_MOD:-/usr/lib/apache2/modules/libphp8.4.so}"
FIXED_MOD="${FIXED_MOD:-/usr/lib/apache2/modules/libphp8.4.so}"

# Kalau mod_php patched tidak ada di sistem, beri pesan jelas (bukan crash cryptic).
if [ ! -f "$FIXED_MOD" ]; then
  echo "ERROR: mod_php patched tidak ditemukan di '$FIXED_MOD'." >&2
  echo "       Set FIXED_MOD=/path/ke/libphp8.4.so (versi 8.4.27+)." >&2
  exit 3
fi

mkdir -p "$RUN/vuln" "$RUN/fixed" "$LAB_DIR/docroot"

gen_conf() {
  local out="$1" port="$2" mod="$3" phpini="$4"
  cat > "$out" <<EOF
ServerRoot "$RUN"
ServerName 127.0.0.1
Listen 127.0.0.1:$port

LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
LoadModule php_module $mod

User $(id -un)
Group $(id -gn)

TypesConfig /etc/mime.types
PidFile "$out.pid"
ErrorLog "$out.error.log"
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{User-Agent}i\"" labfmt
CustomLog "$out.access.log" labfmt
LogLevel info
ServerLimit 4
StartServers 1
MinSpareServers 1
MaxSpareServers 2
MaxRequestWorkers 4

DocumentRoot "$LAB_DIR/docroot"
<Directory "$LAB_DIR/docroot">
    Require all granted
    <FilesMatch "\\.php\$">
        SetHandler application/x-httpd-php
    </FilesMatch>
</Directory>
EOF
}

start_instance() {
  local conf="$1" phpini="$2" tag="$3"
  # PHPRC menunjuk php.ini lab; PHPRC juga diteruskan ke worker prefork.
  PHPRC="$phpini" /usr/sbin/apache2 -f "$conf" -k start 2>>"$conf.start.log"
  sleep 1
}

stop_instance() {
  local conf="$1"
  if [ -f "$conf.pid" ]; then
    kill "$(cat "$conf.pid")" 2>/dev/null
    sleep 1
  fi
}

case "${1:-run}" in
  start)
    gen_conf "$RUN/vuln/httpd.conf"  8091 "$VULN_MOD"  "$LAB_DIR/php.ini.lab"
    gen_conf "$RUN/fixed/httpd.conf" 8092 "$FIXED_MOD" "$LAB_DIR/php.ini.lab"
    start_instance "$RUN/vuln/httpd.conf"  "$LAB_DIR/php.ini.lab" vuln
    start_instance "$RUN/fixed/httpd.conf" "$LAB_DIR/php.ini.lab" fixed
    echo "--- vuln (:8091) ---"; curl -s http://127.0.0.1:8091/info.php
    echo "--- fixed (:8092) ---"; curl -s http://127.0.0.1:8092/info.php
    ;;
  stop)
    stop_instance "$RUN/vuln/httpd.conf"
    stop_instance "$RUN/fixed/httpd.conf"
    echo stopped
    ;;
  *)
    echo "usage: $0 {start|stop}" >&2; exit 2
    ;;
esac
