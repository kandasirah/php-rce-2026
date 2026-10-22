#!/usr/bin/env python3
"""
Cek mitigasi rantai php2shell (CVE-2026-109618 / CVE-2026-109619).

Membaca konfigurasi PHP yang benar-benar dipakai runtime (bukan hanya file
konfigurasi di disk) lalu menilai apakah mitigasi wajib sudah aktif.

Sumber data
-----------
1. `--url <phpinfo|json>` : halaman yang menampilkan phpinfo() atau JSON
   berisi konfigurasi PHP. Contoh:
       python3 defense/check_mitigations.py --url 'http://127.0.0.1:8093/info.php'
2. `--lab`               : otomatis memakai endpoint /info.php milik
   instance lab yang sedang hidup (deteksi lewat exploit/php2shell/labctl.py).
3. `--fpm-port <port>`   : lewat FastCGI ke php-fpm (untuk lab FPM).

Exit code
---------
   0  semua mitigasi wajib terpenuhi
   1  ada mitigasi wajib yang belum aktif
   2  error (target tidak bisa dibaca / di luar loopback)

Mengapa ini penting
-------------------
Mitigasi `session.upload_progress.enabled=0` adalah SATU-SATUNYA langkah
yang menutup rantai A, B, C, dan D sekaligus. Upgrade PHP ke >= 8.4.27
hanya menutup rantai D. Script ini dipakai untuk membuktikan keadaan
nyata di server, bukan sekadar membaca file konfigurasi di disk.
"""
import argparse
import json
import os
import re
import socket
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "exploit", "php2shell"))

import common  # noqa: E402

# (key php.ini, nilai yang dianggap aman, penjelasan, level)
# level: "wajib" = menutup rantai, "opsional" = defense in depth
CHECKS = [
    ("session.upload_progress.enabled", ("0", "off", "false", ""),
     "Menutup rantai A/B/C/D (payload masuk lewat file session)", "wajib"),
    ("session.serialize_handler", ("php",),
     "Menutup rantai C (butuh mismatch handler serializer)", "wajib"),
    ("ffi.enable", ("preload",),
     "Menutup rantai E (FFI = write primitive ke memori proses). "
     "Catatan: 'preload' masih mengizinkan FFI dari file preload; "
     "pastikan tidak ada preload file yang memanggil FFI::cdef", "wajib"),
    ("memory_limit", (),
     "Mitigasi advisory CVE-2026-109618; TIDAK mencegah state bocor",
     "wajib"),
    ("disable_functions", (),
     "Membatasi konsekuensi RCE (bukan closure rantai)", "opsional"),
    ("session.upload_progress.cleanup", (),
     "Membersihkan data progress setelah upload selesai", "opsional"),
]


# Endpoint lab (info.php) memakai nama pendek supaya aman di URL, sedangkan
# nama key php.ini yang sebenarnya sudah dipisah titik (contoh:
# "session.upload_progress.enabled"). Bridge ini memetakan keduanya.
ALIASES = {
    "upload_progress_enabled": "session.upload_progress.enabled",
    "upload_progress_cleanup": "session.upload_progress.cleanup",
    "serialize_handler": "session.serialize_handler",
    "ffi_enable": "ffi.enable",
    "ffi_loaded": "ffi.loaded",
}


def normalize(config):
    """Tambahkan nama key php.ini penuh ke dalam dict konfigurasi."""
    out = dict(config)
    for short, full in ALIASES.items():
        if short in out and full not in out:
            out[full] = out[short]
    return out


def fetch_http(host, port, path, timeout=10):
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    resp = common.raw_http(host, port, req, timeout=timeout)
    head, body = common.split_http(resp)
    return common.http_status(head), common.dechunk(body).decode("latin-1", "replace")


def fetch_fcgi(host, port, script, timeout=10):
    import fcgi

    params = fcgi.build_params(script_name=script, method="GET")
    out, _ = fcgi.FCGIRequest(host, port, timeout=timeout).request(params)
    return out.decode("latin-1", "replace")


def parse_kv(text):
    """Parse output lab (satu `key=value` per baris) jadi dict."""
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            k = k.strip()
            if re.fullmatch(r"[A-Za-z0-9_.]+", k):
                out[k] = v.strip()
    return out


def parse_phpinfo(text):
    """Parse tabel phpinfo() jadi dict key -> value."""
    out = {}
    # pola baris:  <tr><td class="v">nama</td><td class="v">nilai</td></tr>
    for m in re.finditer(
            r"<tr>\s*<td[^>]*>\s*([^<]{1,80}?)\s*</td>\s*<td[^>]*>\s*([^<]{0,200}?)"
            r"\s*</td>\s*</tr>", text, re.S):
        key = re.sub(r"\s+", " ", m.group(1)).strip()
        val = re.sub(r"\s+", " ", m.group(2)).strip()
        if key and key not in out:
            out[key] = val
    # phpinfo >= 8.1 memakai <dt>...</dt><dd>...</dd> untuk section baru
    for m in re.finditer(
            r"<dt[^>]*>([^<]{1,80}?)</dt>\s*<dd[^>]*>(.*?)</dd>", text, re.S):
        key = re.sub(r"\s+", " ", m.group(1)).strip()
        val = re.sub(r"<[^>]+>", "", m.group(2))
        val = re.sub(r"\s+", " ", val).strip()
        if key:
            out.setdefault(key, val)
    return out


def parse_json(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def fetch_config(args, url=None):
    """Kembalikan (label, dict konfigurasi)."""
    if args.fpm_port:
        script = os.path.join(args.docroot, args.script.lstrip("/"))
        text = fetch_fcgi(args.host, args.fpm_port, script)
        return f"fastcgi://{args.host}:{args.fpm_port}{args.script}", parse_kv(text)

    if url:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or args.host
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        status, text = fetch_http(host, port, path)
        if status == 0:
            raise RuntimeError(f"target tidak merespons (status 0): {url}")
        if text.lstrip().startswith("{"):
            return url, parse_json(text)
        data = parse_kv(text)
        if not data:
            data = parse_phpinfo(text)
        return url, data

    raise RuntimeError("tidak ada sumber konfigurasi")


def evaluate(config):
    """Nilai tiap cek; hasil: list of dict."""
    config = normalize(config)
    results = []
    for key, allowed, note, level in CHECKS:
        raw = config.get(key)
        if raw is None:
            results.append(dict(key=key, value=None, ok=None, level=level,
                                note=note, verdict="tidak terbaca"))
            continue
        val = str(raw).strip()
        if key == "memory_limit":
            # -1 = tidak ada batas -> risiko OOM yang bisa dikendalikan
            ok = val not in ("-1", "0", "")
            verdict = "OK (batas finite)" if ok else "BAHAYA (tidak ada batas memori)"
        elif key == "disable_functions":
            listed = {f.strip() for f in val.split(",") if f.strip()}
            wanted = {"system", "exec", "shell_exec", "passthru", "proc_open"}
            missing = wanted - listed
            ok = not missing
            if ok:
                verdict = "OK (semua fungsi eksekusi dimatikan)"
            elif not listed:
                verdict = "BAHAYA (tidak ada fungsi yang dimatikan)"
            else:
                verdict = ("sebagian dimatikan, masih aktif: "
                           + ", ".join(sorted(missing)))
        elif key == "session.upload_progress.cleanup":
            ok = val.strip().lower() in ("1", "on", "true")
            verdict = "OK (cleanup aktif)" if ok else "OFF (progress tidak dibersihkan)"
        else:
            norm = val.strip().lower()
            ok = norm in allowed
            verdict = "OK" if ok else f"BAHAYA (nilai saat ini: {val!r})"
        results.append(dict(key=key, value=val, ok=ok, level=level,
                            note=note, verdict=verdict))
    return results


def main():
    ap = argparse.ArgumentParser(
        description="cek mitigasi rantai php2shell pada konfigurasi PHP runtime")
    ap.add_argument("--url", default="",
                    help="URL endpoint yang menampilkan konfigurasi PHP "
                         "(phpinfo atau JSON)")
    ap.add_argument("--fpm-port", type=int, default=0,
                    help="ambil konfigurasi lewat FastCGI dari php-fpm")
    ap.add_argument("--script", default="/info.php",
                    help="path script yang menampilkan konfigurasi (default /info.php)")
    ap.add_argument("--docroot",
                    default=os.path.join(REPO, "exploit", "php2shell", "lab", "docroot"),
                    help="docroot instance FPM")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--lab", action="store_true",
                    help="cek SEMUA instance lab yang sedang hidup")
    args = ap.parse_args()

    try:
        common.ensure_loopback(args.host)
    except common.LabScopeError as e:
        common.die(str(e), 2)

    targets = []
    if args.lab:
        import labctl

        for name, spec in sorted(labctl.INSTANCES.items(), key=lambda kv: kv[1]["port"]):
            if not labctl.is_running(name):
                continue
            targets.append((f"{name} ({spec['label']})", spec["port"],
                            spec["kind"], name))
        if not targets:
            common.die("tidak ada instance lab yang hidup. "
                       "jalankan: python3 exploit/php2shell/labctl.py start all", 2)
    else:
        targets.append((args.url or f"fastcgi://{args.host}:{args.fpm_port}",
                        args.fpm_port, "fpm" if args.fpm_port else "http", None))

    all_results = []
    exit_code = 0

    for label, port, kind, inst_name in targets:
        try:
            if kind == "fpm":
                script = os.path.join(args.docroot, args.script.lstrip("/"))
                text = fetch_fcgi(args.host, port, script)
                cfg = parse_kv(text)
                src = f"fastcgi://{args.host}:{port}{args.script}"
            else:
                url = args.url if args.url else f"http://{args.host}:{port}{args.script}"
                status, text = fetch_http(args.host, port, args.script)
                if status == 0:
                    raise RuntimeError("tidak merespons")
                cfg = parse_kv(text)
                if not cfg:
                    cfg = parse_phpinfo(text)
                src = url
        except Exception as e:  # noqa: BLE001
            common.log(f"{label}: GAGAL membaca konfigurasi ({e})", "err")
            exit_code = 2
            continue

        res = evaluate(cfg)
        all_results.append(dict(target=label, source=src, checks=res))
        if not args.json:
            print()
            print(f"=== {label}")
            print(f"    sumber: {src}")
            for r in res:
                mark = {True: "[+]", False: "[!]", None: "[*]"}.get(r["ok"], "[*]")
                level = "wajib   " if r["level"] == "wajib" else "opsional"
                print(f"  {mark} {r['key']:38s} = {r['value']!r:22s} {level}")
                print(f"      {r['verdict']} -- {r['note']}")

        for r in res:
            if r["level"] == "wajib" and r["ok"] is False:
                exit_code = 1

    if args.json:
        print(json.dumps(all_results, indent=2, ensure_ascii=False))

    print()
    if exit_code == 1:
        common.log("ADA mitigasi wajib yang belum aktif (lihat tanda [!])", "warn")
    elif exit_code == 2:
        common.log("ada target yang tidak bisa dibaca", "err")
    else:
        common.log("semua mitigasi wajib aktif", "ok")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
