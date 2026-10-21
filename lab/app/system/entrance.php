<?php
/**
 * Dispatcher MetInfo-style untuk lab lokal.
 * URL: /app/system/entrance.php?n=include&m=module&c=weixin&a=doapi
 *
 * Lab lokal 127.0.0.1 saja.
 *
 * Catatan: parsing XML dilakukan manual (regex + entity decode) agar lab tidak
 * bergantung pada extension simplexml/dom yang belum tentu terpasang.
 * MetInfo asli memakai parser XML internal; mekanika vuln-nya tidak berubah.
 */
define('IN_MET', true);
define('PATH_ROOT', dirname(__DIR__) . '/');
define('PATH_CACHE', PATH_ROOT . 'cache/');

require_once PATH_ROOT . 'system/include/class/cache.class.php';
require_once PATH_ROOT . 'system/include/class/weixinreply.class.php';

/**
 * Decode entity XML yang relevan untuk payload:
 * &#x26; / &#38; -> & ,  &amp; -> & ,  &lt; -> < ,  &gt; -> > ,  &quot; -> "
 */
function xml_decode_entities($s)
{
    $map = array(
        '&#x26;' => '&',
        '&#X26;' => '&',
        '&#38;'  => '&',
        '&amp;'  => '&',
        '&lt;'   => '<',
        '&gt;'   => '>',
        '&quot;' => '"',
        '&apos;' => "'",
    );
    return strtr($s, $map);
}

/**
 * Parse tag->value dari XML datar.
 * Elemen root dibuang dulu, lalu diambil tag daun (value tanpa tag anak).
 */
function parse_flat_xml($raw)
{
    // buang elemen root terluar, mis. <x>...</x>
    if (preg_match('#^<([A-Za-z_][A-Za-z0-9_:-]*)\s*>(.*)</\1>\s*$#s', $raw, $root)) {
        $raw = $root[2];
    }

    $data = array();
    if (!preg_match_all('#<([A-Za-z_][A-Za-z0-9_:-]*)\s*>(.*?)</\1>#s', $raw, $m, PREG_SET_ORDER)) {
        return $data;
    }
    foreach ($m as $tag) {
        $key = $tag[1];
        $inner = $tag[2];
        if (strpos($inner, '<') !== false) {
            continue; // bukan tag daun -> skip
        }
        $val = xml_decode_entities($inner);
        if (!array_key_exists($key, $data)) {
            $data[$key] = $val;
        }
    }
    return $data;
}

$raw = file_get_contents('php://input');
$data = ($raw === false || $raw === '') ? array() : parse_flat_xml($raw);

$n = isset($_GET['n']) ? $_GET['n'] : '';
$m = isset($_GET['m']) ? $_GET['m'] : '';
$c = isset($_GET['c']) ? $_GET['c'] : '';
$a = isset($_GET['a']) ? $_GET['a'] : '';

if ($n === 'include' && $m === 'module' && $c === 'weixin' && $a === 'doapi') {
    $reply = new weixinreply();
    echo $reply->doapi($data);
    exit;
}

echo 'error';
