<?php
/**
 * Rekonstruksi RAPUH dari MetInfo CMS <= 8.1
 * app/system/weixin/include/class/weixinreply.class.php
 *
 * Method wxAdminLogin() disalin apa adanya dari advisory KIS-2026-06.
 * Lab lokal 127.0.0.1 saja.
 */
class weixinreply
{
    /**
     * Entry point modul weixin: app/system/entrance.php?n=include&m=module&c=weixin&a=doapi
     */
    public function doapi($data)
    {
        if (isset($data['Event']) && $data['Event'] === 'SCAN') {
            $eventKey = isset($data['EventKey']) ? $data['EventKey'] : '';
            $parts = explode('&', $eventKey, 2);
            $action = $parts[0];
            $code = isset($parts[1]) ? $parts[1] : '';

            if ($action === 'adminlogin') {
                $this->wxAdminLogin($data, $code);
                echo 'success';
                return;
            }
        }

        echo 'fail';
    }

    /**
     * 149  public function wxAdminLogin($data = array(),$code = '')
     * 150  {
     * 151      global $_M;
     * 152      $weixinapi = load::mod_class('weixin/weixinapi','new');
     * 153      $login_code = cache::get("weixin/".$code);
     * 154       if ($login_code) {
     * 155          cache::put("weixin/".$login_code,$data['FromUserName']);
     * 156       }
     * 157      return;
     * 158  }
     */
    public function wxAdminLogin($data = array(), $code = '')
    {
        $login_code = cache::get("weixin/" . $code);   // VULN #1: path traversal -> include
        if ($login_code) {
            cache::put("weixin/" . $login_code, $data['FromUserName']);  // VULN #2: code injection
        }
        return;
    }
}
