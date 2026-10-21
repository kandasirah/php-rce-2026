# Security Policy

## Cakupan repo ini

Repo ini adalah **lab riset keamanan** berisi PoC exploit yang terbukti
jalan (bukan teori) untuk CVE yang advisori dan PoC publiknya sudah
dirilis lebih dulu:

| CVE | Produk | Status advisori |
|---|---|---|
| CVE-2026-29014 | MetInfo CMS ≤ 8.1 | Advisory + PoC publik: KIS-2026-06 |
| CVE-2026-109618 | PHP 8.4.x (core) | Advisory publik php-src: GHSA-w8hw-w9fx-j79w |
| CVE-2026-109619 | PHP 8.4.x (core) | Advisory publik php-src: GHSA-6wmf-4rv5-p3rp |

Target lab adalah **replika** yang ditulis ulang dari potongan kode pada
advisory, bukan instalasi CMS produksi. Seluruh eksploitasi di repo ini
dijalankan terhadap `127.0.0.1` saja.

## Yang dianggap penyalahgunaan

* Menjalankan `exploit/exploit.py` terhadap host, IP, atau domain **milik
  pihak lain** tanpa izin tertulis.
* Menggunakan `exploit/payload_gen.py` untuk membangun payload terhadap
  sistem produksi.
* Men-deploy artefak di `defense/` ke server produksi tanpa pengujian
  terlebih dahulu. Aturan ModSecurity yang terlalu agresif bisa merusak
  layanan (false positive).

## Kalau kamu menemukan masalah di repo ini

* **Bug di kode lab / skrip verifikasi:** buka issue di repo ini.
* **Kerentanan pada produk yang diuji** (MetInfo / PHP): laporkan ke vendor
  sesuai kebijakan disclosure mereka, **bukan** lewat issue publik.
  - MetInfo: kanal advisori resmi Karmain Security (KIS-2026-06).
  - PHP: <https://github.com/php/php-src/security/advisories>

## Contoh penggunaan yang benar

```bash
# 1. lab lokal (aman)
cd lab && python3 serve.py --port 8099
python3 exploit/exploit.py -t http://127.0.0.1:8099 -c 'id'

# 2. uji deteksi di server milik sendiri atau lab internal
python3 defense/ioc_hunt.py --fs /var/www/html
```
