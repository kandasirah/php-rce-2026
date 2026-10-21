# Hasil Diferensial — CVE-2026-109618 & CVE-2026-109619 (PHP core)

Pengukuran nyata pada **localhost** (`127.0.0.1`) membandingkan dua build
PHP di bawah Apache + mod_php (SAPI yang dikonfirmasi rentan oleh advisory):

| Instance | Port | Build | Status |
|---|---|---|---|
| vulnerable | 8091 | PHP **8.4.11** (mod_php bawaan Kali) | < 8.4.27 → rentan |
| patched | 8092 | PHP **8.4.27** (mod_php dari Debian security pool) | sudah dipatch |

Semua pengukuran: `memory_limit=32M`, `post_max_size=16M`, prefork MPM,
`ServerLimit 4 / MaxRequestWorkers 4`.

Reproduksi: `./apache_diff.sh start && ./run_diff.sh`

---

## 1. Konfirmasi versi

```
  :8091 [vulnerable] PHP=8.4.11 SAPI=apache2handler MEMLIMIT=32M
  :8092 [patched ] PHP=8.4.27 SAPI=apache2handler MEMLIMIT=32M
```

---

## 2. Vektor utama: amplifikasi memori header part multipart

Satu POST `multipart/form-data` dengan satu part yang berisi N header pendek
(`X:\r\n`, 4 byte di wire).

| N header | ukuran wire | 8.4.11 (vulnerable) | 8.4.27 (patched) |
|---:|---:|---:|---:|
| 25.000 | 0,10 MB | 8.149.960 B | 411.624 B |
| 50.000 | 0,19 MB | 15.949.960 B | 350.104 B |
| 100.000 | 0,38 MB | 31.549.960 B | 350.104 B |
| 200.000 | 0,76 MB | **HTTP 500 — OOM saat startup** | 350.104 B |
| 300.000 | 1,14 MB | **HTTP 500 — OOM saat startup** | 350.104 B |

(`PEAK_USED` = `memory_get_peak_usage(false)`, byte heap yang benar-benar dipakai.)

**Analisis:**

* Build vulnerable: **≈315 byte heap per header**, sementara representasi di
  wire hanya **4 byte** → **amplifikasi ≈ 79×**.
  100.000 header (0,38 MB di wire) sudah menghabiskan 31,5 MB heap —
  hampir seluruh `memory_limit` 32 MB, dari body yang ukurannya < 0,5 %.
* Build patched: memori **konstan ~350 KB** berapa pun N-nya. Part header
  tidak lagi ditumpuk di memori → vektor amplifikasi ini dihilangkan oleh
  patch.

---

## 3. OOM saat request startup (trigger CVE-2026-109618)

Request yang sama dengan N = 200.000:

```
[vuln  :8091]   0.08s  HTTP/1.0 500 Internal Server Error
    OOM    : PHP Fatal error:  Allowed memory size of 33554432 bytes exhausted
              (tried to allocate 4096 bytes) in Unknown on line 0
[fixed :8092]  0.02s  HTTP/1.1 200 OK
              PHP=8.4.27 SAPI=apache2handler MEMLIMIT=32M
              PEAK=4194304 PEAK_USED=350104 FILES=1 POST=0
```

Perhatikan detail **`in Unknown on line 0`**: OOM terjadi **sebelum skrip
aplikasi dieksekusi**, yaitu pada fase *request startup* saat PHP mem-parsing
body multipart otomatis.

Ini persis skenario yang dideskripsikan advisory:

> "Apache mod_php unconditionally invokes the request shutdown procedure, even
> when request startup has failed. During request startup, automatic body
> parsing can exhaust the configured memory limit and exit the request in a
> context where state is temporarily invalid. Shutdown then processes this
> invalid state. This happens entirely before any application-specific code
> begins execution."

Pada build vulnerable, OOM tersebut diproses lewat `longjmp()` — keluar paksa
dari konteks startup, meninggalkan state request dalam keadaan invalid, lalu
prosedur shutdown memproses state invalid itu (jalur UAF/CWE-416 yang
menghasilkan RCE).

Pada build patched, jalur tersebut dihapus: `longjmp()` untuk OOM diganti
*soft OOM* yang tertunda di VM safe point berikutnya + *hard OOM* via
`_exit()` bila ambang memori kedua terlampaui, sehingga prosedur shutdown
tidak pernah melihat state invalid.

---

## 4. Vektor lain: file control kosong

`max_file_uploads = 1000`, tapi 6.000 file control kosong tetap menghasilkan
`FILES=6000` — file control kosong **tidak dihitung** terhadap
`max_file_uploads`, sesuai advisory. Biaya memorinya **sama** di kedua build:

| N file control kosong | ukuran wire | 8.4.11 | 8.4.27 |
|---:|---:|---:|---:|
| 1.000 | 0,11 MB | 1.159.376 B | 1.159.504 B |
| 2.000 | 0,21 MB | 1.970.256 B | 1.970.384 B |
| 4.000 | 0,43 MB | 3.592.016 B | 3.592.144 B |
| 6.000 | 0,65 MB | 5.459.536 B | 5.459.664 B |

≈810 byte per file control kosong. Jadi vektor ini **tidak** diperbaiki oleh
patch 8.4.27 — mitigasi tetap berupa batas di level WAF/frontend
(`max_file_uploads`, `post_max_size`, `LimitRequestBody`).

---

## 5. Vektor: nama field bersarang

`max_input_nesting_level = 64` sudah membatasi dampaknya:

| N tingkat nesting | 8.4.11 | 8.4.27 |
|---:|---:|---:|
| 100 | 379.800 B | 361.888 B |
| 2.000 | 391.768 B | 373.856 B |

Di PHP 8.4 batas nesting sudah cukup ketat sehingga vektor ini tidak signifikan
dibanding vektor header.

---

## 6. Perilaku OOM saat runtime

Script `docroot/oom.php` alokasi 256 MiB dengan `memory_limit=32M`:

```
  :8091 [vulnerable] http=200
  :8092 [patched ]   http=200
```

Log error:

```
vuln  : PHP Fatal error:  Allowed memory size of 33554432 bytes exhausted
                 (tried to allocate 268435488 bytes) in .../oom.php on line 7
fixed : PHP Fatal error:  Allowed memory size of 33554432 bytes exhausted
                 (tried to allocate 268439552 bytes) in .../oom.php on line 7
```

Bedanya hanya pada **ambang alokasi**: build patched memakai ambang kedua yang
lebih tinggi (268.439.552 B vs 268.435.488 B) sesuai mekanisme soft/hard OOM
yang baru. Keduanya masih mengembalikan HTTP 200 dengan body terpotong dan
worker tetap hidup.

---

## 7. CVE-2026-109619 (stale global state) — status reproduksi

**Tidak ada exploit lengkap yang bisa ditulis ulang di sini.** Bug ini
membutuhkan *heap shaping* yang sangat spesifik. Yang bisa dan sudah dilakukan:

* **Producer terkonfirmasi** = `fatal_error_backtraces` — hanya ada di
  **PHP 8.5**, sedangkan lab ini memakai 8.4.x. Putar ulang “8.5 only”
  berarti membangun PHP 8.5 + patch, yang tidak tersedia di repo Debian
  Kali/Debian 13 saat ini.
* **Producer alternatif** = siklus hidup *session upload progress* — bisa
  direproduksi secara konseptual: request A mempublikasikan state session lalu
  mengalami OOM/fatal (reset terlewat); request B di worker yang sama
  menyentuh state basi sebelum inisialisasi normal. Jalur ini divalidasi
  advisory untuk mod_php **dan** FPM.
* **Consumer** = diagnostik INI sebelum request init — di mod_php harus lewat
  `.htaccess` / `php_value` / `php_admin_*` per-direktori, karena `php.ini`
  biasa adalah konfigurasi startup dan tidak berlaku lintas-request.

Mitigasi yang dapat diterapkan sekarang dan **sudah tercakup** di
[`../defense/php.ini-hardening.ini`](../defense/php.ini-hardening.ini):

```ini
session.upload_progress.enabled = 0   ; memutus jalur producer+consumer sesi
fatal_error_backtraces = 0            ; memutus producer terkonfirmasi (8.5)
pm.max_requests = 1                   ; FPM: paksa worker keluar tiap request
```

Sesuai advisory: **tidak ada mitigasi konfigurasi yang lengkap** — sebagian
state/ekstensi bisa dipublikasikan dan dikonsumsi tanpa jejak log yang
diprediksi. **Upgrade ke ≥ 8.4.27 adalah satu-satunya mitigasi lengkap.**

---

## 8. Ringkasan

| Aspek | 8.4.11 (vulnerable) | 8.4.27 (patched) |
|---|---|---|
| Header per part multipart | ≈315 B/header (≈79× amplifikasi) | tidak ditumpuk (konstan) |
| OOM saat request startup | **terjadi** (longjmp → state invalid) | tidak terjadi / ditangani gracefully |
| Shutdown saat OOM | memproses state invalid (jalur UAF) | tidak melihat state invalid |
| File control kosong | ≈810 B/file, lolos `max_file_uploads` | sama (belum dipatch) |
| Nesting field | dibatasi `max_input_nesting_level` | sama |

**Kesimpulan:** upgrade PHP ke **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** adalah
langkah tunggal yang menutup kedua CVE core ini.
