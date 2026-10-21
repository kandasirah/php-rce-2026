<?php
header('Content-Type: text/plain');
echo "PHP=", PHP_VERSION, " SAPI=", php_sapi_name(), "\n";
echo "MEMLIMIT=", ini_get('memory_limit'), "\n";
echo "PEAK=", memory_get_peak_usage(true), " PEAK_USED=", memory_get_peak_usage(false), "\n";
echo "FILES=", isset($_FILES) ? count($_FILES) : 0,
     " POST=", isset($_POST) ? count($_POST) : 0, "\n";
