#!/usr/bin/env python3
"""
Lab server untuk CVE-2026-29014 (MetInfo CMS <= 8.1 PHP code injection).

Menjalankan lab VULNERABLE di 127.0.0.1 saja. Tidak bind ke interface publik.

    python3 serve.py [--port 8099] [--php /usr/bin/php]

Docroot = direktori lab, sehingga URL endpoint:
    /app/system/entrance.php?n=include&m=module&c=weixin&a=doapi
File .php dieksekusi oleh PHP built-in server (bukan disajikan sebagai teks).
"""
import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--php", default=shutil.which("php") or "php")
    args = ap.parse_args()

    # prasyarat eksploitasi di non-Windows: folder cache/weixin harus ada
    os.makedirs(os.path.join(HERE, "app", "cache", "weixin"), exist_ok=True)

    # fixture wajib: tanpa file ini tahap 1 (path traversal) tidak bisa
    # menghasilkan tahap 2 (include file payload).
    fixture = os.path.join(HERE, "app", "cache", "config", "tables.php")
    if not os.path.exists(fixture):
        print(f"[lab] PERINGATAN: fixture lab tidak ada: {fixture}", file=sys.stderr)
        print("[lab] exploit tahap 1/2 akan gagal (file ini harus ikut ter-deploy).",
              file=sys.stderr)

    url = f"http://127.0.0.1:{args.port}/app/system/entrance.php?n=include&m=module&c=weixin&a=doapi"
    proc = subprocess.Popen(
        [args.php, "-S", f"127.0.0.1:{args.port}", "-t", HERE],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    # kalau `serve.py` mati, anak `php -S` harus ikut mati (tidak ada yatim
    # yang masih memegang port).
    def _cleanup(signum, frame):  # noqa: ARG001
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001
            pass
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT, _cleanup)

    # tunggu server siap
    for _ in range(50):
        time.sleep(0.1)
        try:
            urllib.request.urlopen(url, timeout=1).read()
            break
        except urllib.error.HTTPError:
            break
        except Exception:
            if proc.poll() is not None:
                print("[-] server gagal start", file=sys.stderr)
                return 1

    print(f"[lab] vulnerable MetInfo replica on http://127.0.0.1:{args.port}/")
    print(f"[lab] endpoint: {url}")

    try:
        for line in proc.stdout:
            print("[lab]", line.rstrip(), flush=True)
    except KeyboardInterrupt:
        proc.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
