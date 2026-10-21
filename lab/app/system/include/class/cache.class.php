<?php
/**
 * Rekonstruksi RAPUH dari class "cache" MetInfo CMS <= 8.1.
 *
 * Logika di bawah ini disalin apa adanya dari advisory KIS-2026-06
 * (CVE-2026-29014, ditemukan Egidio Romano / EgiX).
 *
 * File ini HANYA untuk lab lokal di 127.0.0.1. Jangan dipakai di produksi.
 */
class cache
{
    /**
     * VULN #1 — tidak ada normalisasi path.
     * $file datang dari input attacker (EventKey), sehingga "weixin/../config/tables"
     *menjadi path absolut di luar folder cache, dan file .php di sana ikut di-include.
     */
    public static function get($file, $type = 'php')
    {
        $save = PATH_CACHE . $file . '.' . $type;
        if (!file_exists($save)) {
            return false;
        }

        if ($type === 'php') {
            $cache = null;
            include $save;   // <-- include file arbitrer (path traversal)
            return $cache;   // <-- isi file yang di-include dikembalikan ke pemanggil
        }

        return file_get_contents($save);
    }

    /**
     * VULN #2 — escaping dinonaktifkan (baris di-comment di kode asli).
     * Data mentah ditulis ke dalam file .php di dalam double-quote,
     * sehingga ekspresi ${...} dieksekusi saat file di-include.
     */
    public static function put($file, $data, $type = 'php')
    {
        $save = PATH_CACHE . $file . '.' . $type;
        makefile($save);

        // Baris ini dinonaktifkan pada MetInfo <= 8.1 -> CWE-94 (PHP code injection)
        //$data = str_replace(array("\"", "\\"), array("\\\"", "\\\\"), $data);

        if (!is_array($data)) {
            file_put_contents(
                $save,
                "<?php\ndefined('IN_MET') or exit('No permission');\n\$cache=\"{$data}\";\n?>"
            );
        } else {
            $info = var_export($data, true);
            $info = "<?php\ndefined('IN_MET') or exit('No permission');\n\$cache = {$info};\n?>";
            file_put_contents($save, $info);
        }
    }
}

/**
 * MetInfo memindahkan helper ini ke file terpisah; disatukan agar lab mandiri.
 */
function makefile($file)
{
    $dir = dirname($file);
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }
}
