<?php
// Memicu OOM di dalam script (setelah request startup selesai).
// Tujuan: membandingkan perilaku OOM saat runtime antara build vulnerable
// (longjmp) dan build patched (soft OOM di VM safe point / hard OOM _exit()).
header('Content-Type: text/plain');
echo "before-oom\n";
$buf = str_repeat('A', 1 << 28);   // 256 MiB >> memory_limit
echo "after-oom len=", strlen($buf), "\n";
