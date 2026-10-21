#!/usr/bin/env python3
"""
Verifikasi end-to-end lab RCE PHP.

Menjalankan serangkaian pemeriksaan dan keluar dengan kode 0 hanya bila SEMUA
langkah kritis lolos:

  1. Lab server (php -S) menyala di 127.0.0.1 (default 8098, instance sendiri)
  2. Endpoint MetInfo meniru perilaku produksi (200 + 'success')
  3. Exploit tahap 2 mengeksekusi perintah -> RCE terbukti
  4. Tahap 1 exploit menulis file cache/weixin/Array.php (write primitive)
  5. Semua 6 varian payload AI-assisted berhasil (payload_gen --validate)
  6. Deteksi IOC menemukan artefak penyerang di filesystem
  7. (opsional) Diferensial PHP core: instance vulnerable OOM, patched tidak

Pakai:
    python3 verify/verify_lab.py                    # hermetik: instance sendiri
    python3 verify/verify_lab.py --port 8098        # ganti port instance sendiri
    python3 verify/verify_lab.py --target http://127.0.0.1:8099
    python3 verify/verify_lab.py --skip-core        # lewati cek core CVE
    python3 verify/verify_lab.py --json

Catatan: secara default verifier menyalakan instance lab KHUSUS miliknya
di port 8098 lalu mematikannya lagi di akhir. Ini supaya hasil verifikasi
tidak tertukar dengan lab lain yang kebetulan jalan di port 8099 (mis. dari
checkout berbeda).
"""
import argparse
import atexit
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
DEFAULT_PORT = 8098
MARK = "_____"

results = []
_child_procs = []


def record(name, ok, detail="", skipped=False):
    results.append({"name": name, "ok": bool(ok), "detail": detail, "skipped": skipped})
    if skipped:
        print(f"  [SKIP] {name}" + (f" -- {detail}" if detail else ""))
    else:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    return ok


def http_get(url, timeout=5):
    """GET; kembalikan (status, body, headers) atau (None, err, {})"""
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace"), dict(r.headers)
    except Exception as e:  # noqa: BLE001
        return None, str(e), {}


def lab_fingerprint(target):
    """Ambil X-Lab-Root dari server; None bila tidak hidup / bukan lab kita."""
    st, _, hdrs = http_get(target + ENDPOINT, timeout=3)
    if st is None:
        return None
    return hdrs.get("X-Lab-Root")


def start_lab(port):
    """Nyalakan instance lab KHUSUS untuk verifikasi.

    Returns (ok, message, proc). Server yang sudah ada di port tsb hanya
    dipakai bila X-Lab-Root-nya cocok dengan checkout ini.
    """
    target = f"http://127.0.0.1:{port}"
    fp = lab_fingerprint(target)
    if fp is not None:
        if os.path.normpath(fp) == os.path.normpath(LAB_DIR):
            return True, f"instance lab checkout ini sudah jalan di :{port}", None
        return False, (f"port {port} dipakai instance lab lain (root={fp}); "
                       f"pakai --port lain"), None

    os.makedirs(CACHE_DIR, exist_ok=True)
    log_path = os.environ.get(
        "VERIFY_LAB_LOG", os.path.join(tempfile.gettempdir(), "php-rce-2026-verify.log"))
    log = open(log_path, "ab")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(LAB_DIR, "serve.py"), "--port", str(port)],
        cwd=LAB_DIR, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    _child_procs.append(proc)
    for _ in range(50):
        time.sleep(0.2)
        if proc.poll() is not None:
            return False, f"serve.py berhenti (lihat {log_path})", proc
        fp = lab_fingerprint(target)
        if fp is not None:
            if os.path.normpath(fp) != os.path.normpath(LAB_DIR):
                return False, f"server di :{port} bukan instance checkout ini (root={fp})", proc
            return True, f"lab dinyalakan di :{port}", proc
    return False, "lab gagal dinyalakan", proc


def stop_lab():
    """Matikan instance lab yang kita nyalakan sendiri."""
    for proc in _child_procs:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception:  # noqa: BLE001
            pass
    _child_procs.clear()


def check_lab_up(target):
    st, body, _ = http_get(target + ENDPOINT, timeout=5)
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
    st_v, _, _ = http_get("http://127.0.0.1:8091/info.php", timeout=3)
    st_f, _, _ = http_get("http://127.0.0.1:8092/info.php", timeout=3)
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
    ap.add_argument("--target", default=None,
                    help="verifikasi instance yang sudah ada (default: instance sendiri di --port)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help=f"port untuk instance lab verifikasi (default {DEFAULT_PORT})")
    ap.add_argument("--skip-core", action="store_true", help="lewati cek diferensial core CVE")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    print("== Verifikasi lab RCE PHP ==")
    atexit.register(stop_lab)

    external = args.target is not None
    target = args.target or f"http://127.0.0.1:{args.port}"

    if not external:
        ok, msg, _ = start_lab(args.port)
        print(f"  [INFO] {msg}")
        if not ok:
            record("lab server menyala", False, msg)
            return 1
    else:
        fp = lab_fingerprint(target)
        if fp is None:
            record("lab server menyala", False, f"tidak ada lab di {target}")
            return 1
        same = os.path.normpath(fp) == os.path.normpath(LAB_DIR)
        print(f"  [INFO] target eksternal {target} (root={fp}) "
              f"{'-> cek filesystem lokal valid' if same else '-> cek filesystem lokal DILEWATI'}")
        if not same:
            record("write primitive (cache/weixin/Array.php)", True,
                   "dilewati: target bukan checkout ini", skipped=True)
            record("deteksi IOC artefak penyerang", True,
                   "dilewati: target bukan checkout ini", skipped=True)

    check_lab_up(target)
    check_endpoint(target)
    # exploit menulis ulang artefak cache dengan payload sungguhan -> cek file
    check_rce(target)
    check_write_primitive()
    check_payload_variants(target)
    check_ioc_detection()
    if not args.skip_core:
        check_core_diff()

    scored = [r for r in results if not r["skipped"]]
    passed = sum(1 for r in scored if r["ok"])
    total = len(scored)
    skipped = len(results) - total
    print()
    print(f"== {passed}/{total} pemeriksaan lolos ==" + (f" ({skipped} dilewati)" if skipped else ""))

    if args.json:
        print(json.dumps({"passed": passed, "total": total, "skipped": skipped, "results": results},
                         indent=2, ensure_ascii=False))
    stop_lab()
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
