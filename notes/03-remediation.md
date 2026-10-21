# Remediasi & Checklist Deployment

Dokumen ini adalah daftar tindakan yang harus dilakukan di server yang
terdampak. Diurutkan dari **paling penting** ke paling pelengkap.

---

## P1 — Patch interpreter (menutup 2 CVE core RCE)

```bash
# Debian / Ubuntu
apt-get update
apt-get install --only-upgrade php8.4-cli php8.4-cgi php8.4-fpm php8.4-common libapache2-mod-php8.4
php -v      # harus >= 8.4.27 (atau 8.3.36 / 8.2.35 / 8.5.12)

# RHEL / Alma / Rocky (AppStream)
dnf update php php-cli php-fpm php-common
# atau dari SCL/EPEL sesuai distro Anda
```

Restart **semua** worker — release baru hanya berlaku setelah worker baru:

```bash
systemctl restart php8.4-fpm        # FPM
systemctl restart apache2            # mod_php
```

Cek versi yang benar-benar termuat:

```bash
php -v
curl -s http://127.0.0.1/info.php | grep PHP=     # untuk mod_php
```

> Untuk Apache + mod_php, `apache2ctl -M | grep php_module` memastikan modul
> termuat, dan `info.php` memastikan versinya — kadang `libphp` versi lama
> masih tertinggal di `moduldir` walau paket sudah di-upgrade.

**Kenapa ini non-negotiable:** advisory menyatakan upgrade ke rilis berisi patch
adalah satu-satunya mitigasi lengkap untuk CVE-2026-109618 maupun
CVE-2026-109619. Tidak ada setelan konfigurasi yang menutup semua jalur.

---

## P1 — Patch aplikasi (menutup CVE-2026-29014)

* MetInfo ≤ 8.1 → upgrade ke rilis yang sudah dipatch (≥ 8.2) atau patch
  manual sesuai advisory vendor.
* Kalau endpoint WeChat callback tidak dipakai: **nonaktifkan** route
  `?n=include&m=module&c=weixin&a=doapi` di reverse proxy.
* Kalau dipakai: pastikan callback memvalidasi `msg_signature`/`token`
  WeChat, bukan menerima XML mentah.

---

## P1 — Matikan PHP engine di direktori cache/upload

Ini mitigasi paling pragmatis untuk CVE-2026-29014: exploit bekerja dengan
menulis file `.php` lalu meng-*include*-nya. Kalau PHP tidak dieksekusi di
direktori tersebut, "write file" tidak lagi berarti RCE.

```apache
<DirectoryMatch "^/var/www/.*/(cache|upload|uploads|tmp|data)/">
    php_admin_flag engine Off
    <FilesMatch "\.(?i:ph(?:p[0-9.]*|ar|tml|ps|t)|inc|hphp)$">
        Require all denied
    </FilesMatch>
</DirectoryMatch>
```

Lihat `../defense/apache-hardening.conf` untuk versi lengkapnya.

---

## P1 — Mitigasi konfigurasi untuk CVE-2026-109619

```ini
; putus jalur producer+consumer session upload progress
session.upload_progress.enabled = 0

; putus producer terkonfirmasi (relevan untuk PHP 8.5)
fatal_error_backtraces = 0
```

> Untuk FPM, tambahan (kalau tidak bisa upgrade Segera):
> `pm.max_requests = 1` — memaksa worker keluar setelah satu request sehingga
> state basi tidak pernah dipakai request berikutnya. Ada biaya performa nyata.

---

## P2 — Mitigasi sementara untuk CVE-2026-109618

Selama window upgrade,ZVровой mitigasi dari advisory:

```ini
memory_limit = -1
post_max_size = 16M
max_file_uploads = 20
max_input_nesting_level = 16
```

Dan di frontend:

```nginx
# nginx
client_max_body_size 16m;
```

```apache
# Apache
LimitRequestBody 16777216
```

**PENTING:** `memory_limit = -1` menghapus batas OOM yang bisa dikendalikan
penyerang, tapi **bukan** mitigasi lengkap — kalau `mmap()` gagal, PHP masih
bisa memakai `longjmp()`. Dan **jangan** memakai `RLIMIT_AS` / `RLIMIT_DATA`:
advisory menyatakan keduanya justru memicu `mmap()` gagal → masuk ke jalur
`longjmp()` yang rentan.

Setelah PHP ≥ 8.4.27 terpasang, **kembalikan `memory_limit` ke nilai finite**
(mis. `256M`) dan pastikan tidak ada pool/direktori/aplikasi yang menimpanya.

---

## P2 — WAF

```bash
cp defense/modsecurity-rules.conf /etc/modsecurity/owasp-crs/custom-rules-before-crs.conf
a2enmod security2
apachectl configtest && systemctl reload apache2
```

Aturan mencakup: endpoint MetInfo, path traversal, `${...}`, fungsi eksekusi
PHP, blob base64, rantai `chr()`, header transport payload, dan
multipart header flood.

Uji di produksi (non-destruktif):

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  'http://TARGET/app/system/entrance.php?n=include&m=module&c=weixin&a=doapi' \
  --data-binary '<x><EventKey>adminlogin&#x26;../config/tables</EventKey></x>'
# 403 = aturan aktif; 200 = aturan belum terpasang/berlalu
```

---

## P2 — Audit log (IOC hunting)

```bash
python3 defense/ioc_hunt.py --all /var/log/apache2
python3 defense/ioc_hunt.py --fs /var/www/html
```

Yang dicari (lihat tabel lengkap di `../defense/README.md`):

* `adminlogin` + traversal dari IP yang sama → percobaan eksploitasi.
* `Allowed memory size ... exhausted` **di fase startup** (`in Unknown on line 0`)
  → percobaan memicu OOM (CVE-2026-109618).
* `exit signal Segmentation fault` → indikasi heap corruption (pertahankan
  core dump untuk analisis!).
* File `.php` baru di direktori cache yang berisi `$cache="...${"` →
 Artefak payload MetInfo.

Audit INI (untuk CVE-2026-109619) — di server yang **belum** di-upgrade,
jalankan sementara di lingkungan terisolasi:

```ini
log_errors = On
error_log = /var/log/php/error.log
error_reporting = E_ALL
```

Lalu cari di log: warning/deprecation berulang **sebelum** skrip target
berjalan, fatal/parse/uncaught error, `Maximum execution time exceeded`, dan
error yang muncul di route yang dikendalikan penyerang.

> Ingat: tidak adanya error di log **bukan** bukti aman. Log lama bisa
> dikoleksi dengan severity yang disaring, dan sebagian kegagalan terjadi
> sebelum PHP sempat menulis pesannya.

---

## P2 — Audit konfigurasi INI per-direktori (CVE-2026-109619)

Di mod_php, `.htaccess` dan `php_value`/`php_flag`/`php_admin_*` diterapkan
**sebelum** `php_request_startup()` — itulah yang membuat diagnostik INI bisa
jadi "consumer" lintas-request.

```bash
# Cari override per-direktori yang bisa memicu warning/deprecation
grep -rnsE 'php_(value|flag|admin_value|admin_flag)' /var/www/ 2>/dev/null

# Arahkan ke direktori yang tidak mengandung .htaccess
grep -rnsE 'php_(value|flag)' /var/www/ 2>/dev/null

# Direktif yang deterministic deprecated / risky
grep -rnsE 'auto_detect_line_endings|filter\.default|memory_limit|date\.timezone' /etc/php/ /var/www/ 2>/dev/null
```

Tindakan: pindahkan konfigurasi ke `php.ini` atau pool FPM (diterapkan saat
startup, bukan per-request), dan hapus direktif yang sudah deprecated.

---

## P3 — Rotasi kredensial bila ada indikasi kompromis

RCE = akses penuh ke credential yang tersimpan di environment aplikasi:

* password database, user admin CMS
* token API / webhook / OAuth client
* private key di `~/.ssh`, `~/.aws`, `~/.config`
* cookie sesi & JWT signing key

Rotasi **setelah** patch terpasang ( kalau tidak, penyerang bisa masuk lagi
lewat celah yang sama ).

---

## P3 — Hardening umum

```ini
expose_php = Off
allow_url_include = Off
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,dl,show_source
disable_classes = ReflectionFunction,ReflectionMethod,ReflectionClass
display_errors = Off
log_errors = On
```

`disable_functions` + `disable_classes` adalah defense-in-depth: kalau ada RCE
lain yang lolos, privilege escalation via fungsi eksekusi menjadi jauh
lebih sulit. Uji dulu di staging — banyak aplikasi lama memakai `exec()`.

---

## Checklist ringkas

| # | Tindakan | Status |
|---|---|---|
| 1 | Upgrade PHP ke ≥ 8.4.27 / 8.3.36 / 8.2.35 / 8.5.12 | ☐ |
| 2 | Restart semua worker PHP (FPM + Apache) | ☐ |
| 3 | Verifikasi versi yang benar-benar termuat (`php -v`, `info.php`) | ☐ |
| 4 | Patch/upgrade MetInfo (atau nonaktifkan route weixin) | ☐ |
| 5 | `php_admin_flag engine Off` di direktori cache/upload | ☐ |
| 6 | `session.upload_progress.enabled = 0` | ☐ |
| 7 | `fatal_error_backtraces = 0` (kalau PHP 8.5) | ☐ |
| 8 | While upgrading: `memory_limit = -1`, `post_max_size` konservatif | ☐ |
| 9 | `LimitRequestBody` / `client_max_body_size` di frontend | ☐ |
| 10 | Pasang rules ModSecurity | ☐ |
| 11 | Audit log dengan `ioc_hunt.py` | ☐ |
| 12 | Audit override INI per-direktori | ☐ |
| 13 | Rotasi kredensial bila ada indikasi kompromis | ☐ |
| 14 | Setelah upgrade: kembalikan `memory_limit` ke nilai finite | ☐ |
