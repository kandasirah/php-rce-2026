#!/usr/bin/env python3
"""
IOC hunting untuk RCE PHP (CVE-2026-29014 / CVE-2026-109618 / CVE-2026-109619).

Mencari jejak penyerangan di:
  1. File log web (Apache combined/CLF, nginx)
  2. Log error PHP
  3. Filesystem: file .php yang ditulis di direktori cache/upload

Pakai:
    python3 ioc_hunt.py /var/log/apache2/access.log
    python3 ioc_hunt.py --fs /var/www/html
    python3 ioc_hunt.py --all /var/log/apache2
    python3 ioc_hunt.py --json /var/log/apache2/access.log
"""
import argparse
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# IOC: (nama, regex, tingkat)
# ---------------------------------------------------------------------------
LOG_IOCS = [
    ("metinfo-weixin-endpoint",
     re.compile(r"(?:c=weixin|&a=doapi|adminlogin)", re.I), "critical"),
    ("path-traversal",
     re.compile(r"(?:\.\./|%2e%2e[/\\]|%252e%252e)", re.I), "high"),
    ("php-complex-curly",
     re.compile(r"\$\{[^\}]{1,400}\}"), "critical"),
    ("php-eval-base64",
     re.compile(r"(?i)base64_decode\s*\(\s*['\"]?[A-Za-z0-9+/]{40,}"), "critical"),
    ("php-chr-chain",
     re.compile(r"(?i)(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}"), "high"),
    ("php-exec-func",
     re.compile(r"(?i)\b(eval|assert|create_function|passthru|shell_exec|"
                r"proc_open|popen|system)\s*\("), "high"),
    ("server-header-access",
     re.compile(r"(?i)\$_SERVER\s*\[\s*['\"]HTTP_"), "critical"),
    ("payload-header-transport",
     re.compile(r"(?i)\s\"(?:C|C2|Cmd|Payload|X-Cmd)\":\s*\"?[A-Za-z0-9+/]{40,}"), "critical"),
    ("php-error-oom-startup",
     re.compile(r"(?i)Allowed memory size of \d+ bytes exhausted.*in Unknown on line 0"), "critical"),
    ("php-error-oom",
     re.compile(r"(?i)Allowed memory size of \d+ bytes exhausted"), "high"),
    ("php-nesting",
     re.compile(r"(?i)Input variable nesting level exceeded"), "medium"),
    ("php-fatal",
     re.compile(r"(?i)PHP (Fatal error|Parse error|Uncaught)"), "medium"),
    ("max-execution-time",
     re.compile(r"(?i)Maximum execution time exceeded"), "medium"),
    ("worker-crash",
     re.compile(r"(?i)exit signal (Segmentation fault|Bus error)|core dumped"), "critical"),
    ("soap-map-uci",
     re.compile(r"(?i)soap:\s*(?:Map|Array)"), "medium"),
]

FS_IOCS = [
    # pola "cache class" MetInfo: $cache="....";  -> payload tersimpan
    ("cache-php-payload",
     re.compile(r"\$cache\s*=\s*\"[^\"\n]*\$\{"), "critical"),
    ("eval-in-php-file",
     re.compile(r"(?i)\beval\s*\(\s*base64_decode\s*\("), "critical"),
    ("complex-curly-in-php",
     re.compile(r"\$\{[A-Za-z_$][^\}]{0,200}\}"), "critical"),
    ("php-in-cache-dir",
     re.compile(r"^cache/.*\.php$", re.I), "high"),
]


def hunt_log(path, pattern_filter=None):
    hits = []
    try:
        with open(path, "r", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                for name, rx, sev in LOG_IOCS:
                    if pattern_filter and pattern_filter not in name:
                        continue
                    if rx.search(line):
                        hits.append({"file": path, "line": lineno,
                                     "ioc": name, "severity": sev,
                                     "excerpt": line.strip()[:300]})
                        break
    except OSError as e:
        return [{"file": path, "severity": "info", "excerpt": f"tidak bisa dibaca: {e}"}]
    return hits


def hunt_fs(root, pattern_filter=None):
    hits = []
    if not os.path.isdir(root):
        return hits
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not fn.endswith((".php", ".phtml", ".inc", ".txt", ".cache")):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            try:
                with open(full, "r", errors="replace") as f:
                    data = f.read(200_000)
            except OSError:
                continue
            for name, rx, sev in FS_IOCS:
                if pattern_filter and pattern_filter not in name:
                    continue
                if rx.search(data):
                    hits.append({"file": full, "ioc": name, "severity": sev,
                                 "excerpt": rel})
                    break
    return hits


def collect_files(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for dirpath, _d, files in os.walk(p):
                for fn in files:
                    out.append(os.path.join(dirpath, fn))
        elif os.path.isfile(p):
            out.append(p)
    return out


SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


def main():
    ap = argparse.ArgumentParser(description="IOC hunting untuk RCE PHP")
    ap.add_argument("paths", nargs="*", help="file log atau direktori")
    ap.add_argument("--fs", help="root filesystem yang dipindai (mis. /var/www/html)")
    ap.add_argument("--all", action="store_true",
                    help="pindai file log yang diberikan secara rekursif")
    ap.add_argument("--ioc", help="filter nama IOC")
    ap.add_argument("--json", action="store_true", help="output JSON")
    args = ap.parse_args()

    hits = []
    files = []
    if args.all:
        for p in args.paths:
            files += collect_files([p])
    else:
        files = args.paths

    for f in files:
        if os.path.isdir(f):
            hits += hunt_log(os.path.join(f, "error.log"), args.ioc)
        else:
            hits += hunt_log(f, args.ioc)

    if args.fs:
        hits += hunt_fs(args.fs, args.ioc)

    hits.sort(key=lambda h: SEV_ORDER.get(h.get("severity", "info"), 9))

    if args.json:
        print(json.dumps(hits, indent=2, ensure_ascii=False))
        return 0 if hits else 0

    if not hits:
        print("[i] tidak ada IOC yang cocok")
        return 0

    counts = {}
    for h in hits:
        counts[h.get("severity", "info")] = counts.get(h.get("severity", "info"), 0) + 1
    print(f"[!] {len(hits)} temuan: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    print()
    for h in hits:
        loc = f"{h.get('file','')}:{h.get('line','')}" if h.get("line") else h.get("file", "")
        print(f"  [{h.get('severity','').upper():8s}] {h.get('ioc',''):24s} {loc}")
        if h.get("excerpt"):
            print(f"           {h['excerpt'][:220]}")
    print()
    print("Tindakan yang disarankan:")
    print("  1. Periksa file .php di direktori cache/upload (IOC 'cache-php-payload').")
    print("  2. Upgrade PHP ke >= 8.4.27 / 8.3.36 / 8.2.35 / 8.5.12.")
    print("  3. Patch aplikasi MetInfo (CVE-2026-29014) dan rotasi kredensial.")
    print("  4. Audit log untuk 'adminlogin' + traversal dari IP yang sama.")
    return 1 if any(h.get("severity") == "critical" for h in hits) else 0


if __name__ == "__main__":
    sys.exit(main())
