# Artefak Pertahanan

Kumpulan artefak yang bisa dipasang di server produksi untuk memitigasi dan
mendeteksi RCE PHP yang dibahas di lab ini.

| File | Untuk siapa | Tujuan |
|---|---|---|
| `modsecurity-rules.conf` | Tim WAF / AppSec | Rules ModSecurity v3 untuk mendeteksi & memblokir exploit |
| `php.ini-hardening.ini` | Tim Infra / Sysadmin | Hardening PHP + mitigasi sementara CVE-2026-109618/109619 |
| `apache-hardening.conf` | Tim Web / Sysadmin | Batas request, buang header transport payload, matikan PHP engine di direktori cache |
| `ioc_hunt.py` | Blue team / SOC | Memburu jejak penyerangan di log & filesystem |
| `check_mitigations.py` | Tim Infra / Blue team | Cek mitigasi **runtime** (bukan cuma file konfigurasi) — apakah rantai `php2shell` masih bisa jalan |

---

## 1. `modsecurity-rules.conf`

Aturan yang ditulis:

* **CVE-2026-29014** — `id:1001001`–`1001012`
  * endpoint `weixin/doapi` + `adminlogin` (phase 1)
  * path traversal di body/param (`../`, `%2e%2e`) (phase 2)
  * interpolasi `${...}` di body/param (phase 2)
  * fungsi eksekusi PHP & blob base64 & rantai `chr()` (phase 2)
  * header transport payload (`C:`, `C2:`, `Cmd:`, `X-Cmd:`) (phase 1)
  * akses file cache `.php` (phase 1)
* **CVE-2026-109618** — `id:1002001`–`1002004`
  * ≥200 header dalam satu part multipart
  * ≥200 part multipart
  * ≥50 tingkat nesting nama field
  * ≥100 file control kosong
* **CVE-2026-109619** — `id:1003001` (memantau jalur upload; tidak ada signature
  HTTP yang andal karena bug-nya use-after-free antar-request)
* **Umum** — `id:1004001`–`1004003` (signature shell, akses `$_SERVER[HTTP_*]`,
  path OS sensitif) dan rate limit `id:1005001`–`1005002`
* **Rantai `php2shell`** — `id:1006001`–`1006006`
  * `1006001` — tag PHP (`<?php`) di atribut `filename` part multipart
    (vektor penempatan payload file session)
  * `1006002` — simbol internal PHP (`zend_internal_function`, `function_table`,
    `executor_globals`) di atribut `filename` (vektor overwrite handler)
  * `1006003` — nilai field `PHP_SESSION_UPLOAD_PROGRESS` yang memuat `|`
    + serialized blob
  * `1006004` — tag PHP / marker unserialize / `base64_decode` di nilai field
    `PHP_SESSION_UPLOAD_PROGRESS` (vektor `key`)
  * `1006005` — akses langsung ke file `sess_*` lewat parameter (LFI)
  * `1006006` — data session yang **sudah tercemar** payload PHP
    (`upload_progress_*|...s:N:"...<?php`) → bukti state bocor

  > Aturan-aturan ini **deteksi**, bukan pengganti `session.upload_progress.enabled=0`.
  > Kalau mitigasi itu aktif, permintaan payload tidak pernah sampai ke PHP.

Pemasangan:

```bash
cp defense/modsecurity-rules.conf /etc/modsecurity/owasp-crs/custom-rules-before-crs.conf
a2enmod security2
apachectl configtest && systemctl reload apache2
```

> Catatan: `SecRule REQUEST_BODY` hanya bekerja bila body tidak dalam mode
> streaming. Pastikan `SecRequestBodyAccess On` (default) dan
> `SecRequestBodyLimit` cukup besar, atau pakai `SecRequestBodyLimit 13107200`
> agar body >12 MB tidak di-buffer (body besar justru biayanya rendah).

Validasi cepat tanpa menyentuh server produksi:

```bash
apachectl -t          # syntax check
curl -s -X POST 'http://127.0.0.1:8099/app/system/entrance.php?n=include&m=module&c=weixin&a=doapi' \
     --data-binary '<x><EventKey>adminlogin&#x26;../config/tables</EventKey></x>'
# harus mengembalikan 403 dari WAF, bukan 200
```

---

## 2. `php.ini-hardening.ini`

```bash
cp defense/php.ini-hardening.ini /etc/php/8.4/apache2/conf.d/99-hardening.ini
systemctl restart apache2
```

Bagian penting:

* `memory_limit = -1` — **mitigasi sementara** sesuai advisory
  GHSA-w8hw-w9fx-j79w: tanpa batas memori per-request, batas OOM yang bisa
  dikendalikan penyerang hilang. **Kembalikan ke nilai finite (mis. `256M`)
  segera setelah PHP ≥ 8.4.27 terpasang.**
  * Jangan pernah memakai `RLIMIT_AS` / `RLIMIT_DATA` — advisory menyatakan
    itu justru memicu `mmap()` gagal → masuk ke jalur `longjmp()` yang rentan.
* `session.upload_progress.cleanup = On` — hapus data progress begitu upload
  selesai. Jangan `Off`: sisa progress di file session justru kondisi
  "state bocor" yang dipakai rantai D.
* `session.upload_progress.enabled = 0` — **mitigasi paling penting untuk
  rantai `php2shell`**: memutus jalur payload masuk lewat file session, dan
  dengan begitu menutup rantai A, B, C, dan D sekaligus. Patch 8.4.27 hanya
  menutup rantai D, jadi upgrade **tidak cukup** tanpa baris ini.
* `session.serialize_handler = php` — menutup rantai C (mismatch antara
  serializer yang menulis file session dan handler internal yang membacanya).
* `ffi.enable = preload` — menutup rantai E (FFI = write primitive ke memori
  proses). Catatan: `preload` masih mengizinkan FFI dari file preload, jadi
  pastikan tidak ada preload file yang memanggil `FFI::cdef`.
* `fatal_error_backtraces = 0` — memutus "producer" terkonfirmasi pada
  CVE-2026-109619 (hanya relevan untuk PHP 8.5, aman dipasang di 8.4).
* `post_max_size = 16M`, `max_file_uploads = 20`, `max_input_nesting_level = 16`
  — mengurangi risiko DoS dan memperkecil surface amplifier.
* `disable_functions` — defense in depth kalau ada RCE: `exec`, `passthru`,
  `shell_exec`, `system`, `proc_open`, `popen`, `dl`, `show_source`.
* `disable_classes = ReflectionFunction,ReflectionMethod,ReflectionClass` —
  memutus jalur bypass `disable_functions` lewat Reflection.
* `log_errors = On` + `error_reporting = E_ALL` — wajib untuk audit
  CVE-2026-109619; pola serangan selalu meninggalkan jejak di error log.

> `disable_functions` bisa membuat aplikasi lama error (misal `exec` dipakai
> untuk proses PDF). Uji di staging dulu.

---

## 3. `apache-hardening.conf`

```bash
cp defense/apache-hardening.conf /etc/apache2/conf-available/php-rce-hardening.conf
a2enconf php-rce-hardening
apachectl configtest && systemctl reload apache2
```

Isi:

* `LimitRequestBody 16777216` — batas body di frontend, terpisah dari
  `post_max_size` PHP (advisory: enforce ukuran request ter-decode di frontend).
* `RequestHeader unset C early` (+ `C2`, `Cmd`, `Payload`, `X-Cmd`) — membuang
  header transport payload yang dipakai exploit MetInfo.
* `php_admin_flag engine Off` + `Require all denied` untuk
  `cache/`, `upload/`, `uploads/`, `tmp/`, `data/`, `files/` — **ini kunci
  terpenting**: exploit CVE-2026-29014 bekerja dengan menulis file `.php` ke
  direktori cache lalu meng-include-nya. Kalau PHP engine dimatikan di sana,
  primitive "write file" tidak lagi berarti RCE.
* `ServerTokens Prod`, `ServerSignature Off`.

> Sesuaikan regex `DirectoryMatch` dengan struktur direktori aplikasi Anda.

---

## 4. `ioc_hunt.py`

```bash
python3 defense/ioc_hunt.py /var/log/apache2/access.log
python3 defense/ioc_hunt.py --all /var/log/apache2
python3 defense/ioc_hunt.py --fs /var/www/html
python3 defense/ioc_hunt.py --json /var/log/nginx/access.log
```

IOC yang dicari:

| IOC | Arti |
|---|---|
| `metinfo-weixin-endpoint` | Request ke endpoint `weixin/doapi` atau contain `adminlogin` |
| `path-traversal` | `../`, `%2e%2e`, `%252e%252e` |
| `php-complex-curly` | `${...}` (pola payload inti) |
| `php-eval-base64` | `base64_decode('...')` dengan blob panjang |
| `php-chr-chain` | Rantai `chr()` (payload obfuscation) |
| `php-exec-func` | `eval|assert|system|passthru|shell_exec|proc_open|popen` |
| `server-header-access` | `$_SERVER['HTTP_...']` (payload MetInfo) |
| `payload-header-transport` | Header `C`/`C2`/`Cmd` berisi base64 |
| `php-error-oom` | "Allowed memory size ... exhausted" (CVE-2026-109618) |
| `php-error-oom-startup` | OOM yang terjadi **di fase startup** — tanda khas CVE-2026-109618 |
| `php-nesting` | "Input variable nesting level exceeded" |
| `worker-crash` | `exit signal Segmentation fault` (indikasi heap corruption) |
| `cache-php-payload` | File `.php` di direktori cache berisi `$cache="...${"` |

Exit code `1` bila ada temuan `critical` — berguna untuk hook CI/CD atau
SIEM.

Contoh output nyata dari lab:

```
[!] 1 temuan: critical=1

  [CRITICAL] cache-php-payload        /var/www/html/cache/weixin/Array.php
           weixin/Array.php
```

---

## 5. `check_mitigations.py`

Membaca konfigurasi PHP yang **benar-benar dipakai runtime** (bukan hanya
file `.ini` di disk) lalu menilai apakah mitigasi wajib sudah aktif.

```bash
# semua instance lab yang sedang hidup
python3 defense/check_mitigations.py --lab

# satu server
python3 defense/check_mitigations.py --url 'http://127.0.0.1:8093/info.php'

# lewat FastCGI ke php-fpm
python3 defense/check_mitigations.py --fpm-port 8098 --script /info.php

# output JSON untuk CI
python3 defense/check_mitigations.py --lab --json
```

Exit code: `0` semua mitigasi wajib terpenuhi, `1` ada mitigasi wajib yang belum
aktif, `2` target tidak terbaca / di luar loopback.

Yang dicek:

| Kunci | Level | Artinya |
|---|---|---|
| `session.upload_progress.enabled` | wajib | Menutup rantai A/B/C/D sekaligus |
| `session.serialize_handler` | wajib | Menutup rantai C (butuh mismatch handler) |
| `ffi.enable` | wajib | Menutup rantai E (FFI = write primitive ke memori proses) |
| `memory_limit` | wajib | Mitigasi advisory CVE-2026-109618 (tidak mencegah state bocor) |
| `disable_functions` | opsional | Membatasi konsekuensi RCE, bukan menutup rantai |
| `session.upload_progress.cleanup` | opsional | Membersihkan data progress setelah upload |

Contoh output nyata:

```
=== apache-mitigated (Apache + mod_php 8.4.27 (PATCHED + mitigasi))
  [+] session.upload_progress.enabled        = '0'    wajib
      OK -- Menutup rantai A/B/C/D (payload masuk lewat file session)
  [!] memory_limit                           = '-1'   wajib
      BAHAYA (tidak ada batas memori) -- Mitigasi advisory CVE-2026-109618
```

> `ffi.enable = preload` masih mengizinkan FFI dari file **preload**. Pastikan
> tidak ada preload file yang memanggil `FFI::cdef`.

---

## Checklist penerapan (prioritas)

1. **Upgrade PHP** ke 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 — satu-satunya
   mitigasi lengkap untuk CVE-2026-109618 & CVE-2026-109619.
2. **Patch MetInfo** (CVE-2026-29014) atau pasang versi ≥ yang sudah fix;
   nonaktifkan endpoint WeChat callback kalau tidak dipakai.
3. **Matikan PHP engine di direktori cache/upload** (`apache-hardening.conf`).
4. **Pasang aturan WAF** (`modsecurity-rules.conf`) — quickest win.
5. **Audit log** dengan `ioc_hunt.py` untuk melihat apakah sudah dieksploitasi.
6. **Rotasi kredensial** (admin DB, token API, SSH key) bila ada indikasi
   kompromis: RCE = akses penuh ke credential aplikasi.
7. Setelah upgrade, kembalikan `memory_limit` ke nilai finite.
8. **Pasang `session.upload_progress.enabled = 0`.** Ini wajib, bukan opsional:
   patch 8.4.27 hanya menutup satu dari lima rantai yang terverifikasi.
   Verifikasi dengan `python3 defense/check_mitigations.py --url ...`.
9. Kalau FFI tidak dipakai aplikasi, pastikan `ffi.enable = preload` dan tidak
   ada preload file yang memanggil `FFI::cdef`.
