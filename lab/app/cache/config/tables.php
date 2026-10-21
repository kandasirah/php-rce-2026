<?php
/**
 * Cache "config/tables" MetInfo. Di-include oleh cache::get() saat path traversal
 * berhasil, sehingga $login_code berisi ARRAY -> saat dirangkai jadi string
 * menjadi "Array" (PHP: Array to string conversion).
 * Inilah kunci tahap 2 pada exploit: file target menjadi cache/weixin/Array.php
 */
$cache = array(
    'met_table' => array(
        'name' => 'met_table',
        'columns' => array('id', 'name', 'value'),
    ),
    'met_config' => array(
        'site_name' => 'lab',
        'url' => 'http://127.0.0.1',
    ),
);
