<?php

/*
    user.class.php
    (c) Extrick LLC.

    version 1.0 - 2016.11.17
    version 2.0 2019. 4. 5 - 2021. 3.23
    version 3.0 2021. 3.25 -
    version 3.0.2 2021.10. 3 -

    Usage:
      $user = new user();
      $user->login(['login'|'admin'|'auth=N'|'guest']);
---------------------------------------------------------------------*/
class user {
    public $version = '3.0.2';

    public $userid, $auth;
    public $p = array();

    private $stay_login;
    private $multi_login;

    private $expires;
    private $session_u, $guestid;
    private $cookie_set_options, $cookie_del_options;
    private $login_form;
    private $logout_location;
    private $query_string;
    private $cookie_u, $cookie_g, $cookie_s;

    private $db;

    function __construct(){
        include __DIR__.'/user.class.config.php';

        $this->cookie_u = $user_config['cookie_u'];     // user session
        $this->cookie_g = $user_config['cookie_g'];     // guest id
        $this->cookie_s = $user_config['cookie_s'];     // stay login

        $this->db = new mysqli($user_config['db_host'], $user_config['db_user'], $user_config['db_pass'], $user_config['db_name']);

        $this->login_form = $user_config['login_form'];
        $this->logout_location = $user_config['logout_location'];

        $this->stay_login = $user_config['stay_login'];
        if (isset($_COOKIE[$this->cookie_s]) && $_COOKIE[$this->cookie_s]){ $this->stay_login = true; }

        $this->multi_login = $user_config['multi_login'];
        $this->expires = $user_config['expires'];

        $this->cookie_set_options = array(
            'expires' => time() + $this->expires,
            'path' => '/',
            'samesite' => 'lax'
        );

        $this->cookie_del_options = array(
            'expires' => time() - 3600 * 24,
            'path' => '/',
            'samesite' => 'lax'
        );

        // 期限の切れたsessionは削除する
        $sql = "delete from user_session where session_expire < '".date('Y-m-d H:i:s')."'";
        $this->db->query($sql);

        // COOKIEに保存されているユーザーセッションIDを取得する
        $this->session_u = '';
        if (isset($_COOKIE[$this->cookie_u]) && $_COOKIE[$this->cookie_u]){
            $sql = "select userid from user_session where session = '{$_COOKIE[$this->cookie_u]}'";
            $rtn = $this->db->query($sql);
            if ($rtn->num_rows){
                $this->session_u = $_COOKIE[$this->cookie_u];
            }
            $rtn->free();
        }

        // 古い guestid を削除する
        $sql = "delete from users where `auth` = 0 and `password` < '".date('Y-m-d')."'";
        $this->db->query($sql);

        // guestid の有効期限を延長する
        $expires = date('Y-m-d', time() + $this->expires);
        if (isset($_COOKIE[$this->cookie_g]) && $_COOKIE[$this->cookie_g]){
            $g = $_COOKIE[$this->cookie_g];
            $q_g = $this->quote($g);
            $sql = "update users set password = '{$expires}' where userid = {$q_g}";
            $this->db->query($sql);
        }
        // guestid を発行する
        else {
            $e = 1;
            while ($e){
                $g = $this->make_rndstr(32);
                $sql = "select userid from users where userid = '{$g}'";
                $rtn = $this->db->query($sql);
                $e = $rtn->num_rows;
                $rtn->free();
            }
            $sql = "insert into users (userid, password, auth) values ('{$g}', '{$expires}', 0)";
            $this->db->query($sql);
        }

        setcookie($this->cookie_g, $g, $this->cookie_set_options);
        $this->guestid = $g;
    }

    // ログイン
    public function login(){
        $loginparam = '';
        if (func_num_args()){ $loginparam = func_get_arg(0); }

        $query_string = '';
        if (isset($_SERVER['QUERY_STRING']) && $_SERVER['QUERY_STRING']){
            $query_string = $_SERVER['QUERY_STRING'];
        }

        // 強制ログアウト
        if ($query_string == 'logout' ){
            $this->logout();
            header('Location: '.$this->logout_location);   // ログアウト後の遷移先
            exit;
        }

        // loginformからの戻り
        $loginstatus = 0;
        if (isset($_POST['loginname']) && isset($_POST['password'])){
            $q_loginname = $this->quote($_POST['loginname']);
            $sql = "select userid, password, auth from users where loginname = {$q_loginname}";
            $rtn = $this->db->query($sql);
            if (!$rtn->num_rows){   // 入力した loginname が不正
                $this->logout();
                $this->loginform('ログインIDまたはパスワードが違います。');
            }
            list($userid, $hashed_password, $auth) = $rtn->fetch_row();
            $rtn->free();

            /*
                $hashed_password = password_hash($_POST['password'], PASSWORD_BCRYPT);
            */
            if (password_verify($_POST['password'], $hashed_password) || $hashed_password == md5($_POST['password'])){
                $this->userid = $userid;
                $this->auth = $auth;
                $loginstatus++;

                if (isset($_POST['stay_login']) && $_POST['stay_login']){
                    $this->stay_login = true;
                }
                setcookie($this->cookie_s, $this->stay_login, $this->cookie_set_options);

                if ($hashed_password == md5($_POST['password'])){
                    $hashed_password = password_hash($_POST['password'], PASSWORD_BCRYPT);
                    $sql = "update users set password = '{$hashed_password}' where userid = '{$this->userid}'";
                    $this->db->query($sql);
                }
            }
            else {
                $this->logout();
                $this->loginform('ログインIDまたはパスワードが違います。');
            }
        }

        // cookieに保存してあるsessionをチェックする
        else if ($this->session_u){
            $q_session_u = quote($this->session_u);

            $sql = "select userid, stay_login from user_session where session = {$q_session_u}";
            $rtn = $this->db->query($sql);
            if ($rtn->num_rows){
                list($this->userid, $this->stay_login) = $rtn->fetch_row();
                $sql = "select auth from users where userid = '{$this->userid}'";
                $rtn = $this->db->query($sql);
                list($this->auth) = $rtn->fetch_row();
                $rtn->free();
                $loginstatus++;
            }
            else {
                $this->logout();
            }
        }

        // ユーザーIDでログインできていない場合に、引数 'guest' だと、userid <- guestid
        if (!$this->userid && $loginparam == 'guest'){
            $this->userid = $this->guestid;
            $this->auth = 0;
            $this->p = array();
            $loginstatus++;
        }

        // ログイン後の権限チェック
        if ($loginstatus){
            // 管理者ログイン
            if ($loginparam == 'admin' && $this->auth < 9){
                $this->logout();
                $this->loginform('管理者でログインしてください');
            }
            // 権限制限ログイン
            else if (preg_match("/^auth\=([0-9])$/", $loginparam, $matches) && $this->auth < $matches[1]){
                $this->logout();
                $this->loginform('権限がありません');
            }
            // guest を除く、ユーザーログイン
            else if ($loginparam == 'login' && !$this->auth){
                $this->logout();
                $this->loginform();
            }
        }
        else {     // ここまでの処理でログインできていない
            $this->logout();
            $this->loginform();
        }

        // session update
        $this->upd_session();

        // get property
        $sql = "select * from user_property where userid = '{$this->userid}' limit 1";
        $rtn = $this->db->query($sql);
        $this->p = $rtn->fetch_assoc();
        $rtn->free();

        return;
    }

    //
    private function upd_session(){
        if ($this->stay_login){
            $session_expire = date('Y-m-d H:i:s', time() + $this->expires);
        }
        else {
            $session_expire = date('Y-m-d H:i:s', time() + 3600 * 24);
        }

        if ($this->session_u){
            $sql = "update user_session set session_expire = '{$session_expire}' where session = '{$this->session_u}'";
        }
        else {
            $this->session_u = $this->make_session(32);
            $sql = "insert into user_session (session, session_expire, userid, stay_login) values ('{$this->session_u}', '{$session_expire}', '{$this->userid}', {$this->stay_login})";
        }
        $this->db->query($sql);

        // ログインしたままにする
        if ($this->stay_login){
            setcookie($this->cookie_u, $this->session_u, $this->cookie_set_options);
            setcookie($this->cookie_s, '1', $this->cookie_set_options);
        }
        else {
            $cookie_options = array(
                'expires' => 0,
                'path' => '/',
                'samesite' => 'lax'
            );
            setcookie($this->cookie_u, $this->session_u, $cookie_options);
            setcookie($this->cookie_s, '', $this->cookie_del_options);
        }

        if (!$this->multi_login){
            // シングルログイン： 無効な自分のセッションを削除する
            $sql = "delete from user_session where userid='{$this->userid}' and session != '{$this->session_u}'";
            $this->db->query($sql);
        }

        return;
    }

    public function logout(){
        if (!isset($this->userid)){ return; }

        // セッションを削除
        $sql = "delete from user_session where session = '{$this->session_u}'";
        $this->db->query($sql);

        // COOKIEを削除
        setcookie($this->cookie_u, '', $this->cookie_del_options);
        setcookie($this->cookie_s, '', $this->cookie_del_options);
        $this->userid = '';
        $this->auth = 0;
        $this->stay_login = false;

        return;
    }

    private function quote($val){
        return "'" . $this->db->real_escape_string($val) . "'";
    }

    private function make_rndstr($len){
        $seedstr = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $randmax = strlen($seedstr) - 1;
        $rndstr = '';
        for ($i = 1; $i <= $len; $i++){ $rndstr .= substr($seedstr, mt_rand(0, $randmax), 1); }
        return $rndstr;
    }

    private function make_session($len) {
        $e = 1;
        while ($e){
            $session = $this->make_rndstr($len);
            $rtn = $this->db->query("select session from user_session where session = '{$session}' limit 1");
            $e = $rtn->num_rows;
            $rtn->free();
        }
        return $session;
    }

    public function loginform($msg = ''){
        // セッションがスタートしていなかったらスタートする
        if (session_status() !== PHP_SESSION_ACTIVE){
            session_start();
        }
        // $_SERVER['SCRIPT_NAME'] -> user.class.php を呼び出したスクリプト
        $_SESSION['ref'] = $_SERVER['SCRIPT_NAME'];

        // if (isset($this->auth) && $this->auth){ $this->logout(); }
        $this->logout();
        header('Location: '.$this->login_form);
        exit;

/*
        // ログインフォーム 必須項目
        <?php
        session_start();

        // $ref: ログイン後の遷移先
        if (isset($_SESSION['ref']) && $_SESSION['ref']){
            $ref = $_SESSION['ref'];
            unset($_SESSION['ref']);
        }
        else {
            $ref = '/';
        }

        print $msg;

        <form method="POST" action="{$ref}">
        <input type="text" name="loginname" />
        <input type="password" name="password" />
        <input type="submit" value="ログイン" />
        <input type="hidden" name="stay_login" value="1" />
        </form>
*/
    }

    public function useradd($loginname, $password, $auth=1){
        if ($this->auth < 9){ return false; }
        $e = 1;
        while($e){
            $userid = make_session(32);
            $sql = "select userid from users where userid = '{$userid}'";
            $rtn = $this->db->query($sql);
            $e = $rtn->num_rows();
            $rtn->free();
        }
        $q_loginname = $this->quote($loginname);
        $q_password = $this->quote(password_hash($password, PASSWORD_BCRYPT));
        $sql = "insert into users (userid, loginname, password, auth) values ('{$userid}', {$q_loginname}, {$q_password}, {$auth})";
        $this->db->query($sql);
        $sql = "insert into user_property (userid) values ('{$userid}')";
        $this->db->query($sql);
        return $userid;
    }

    public function userdel($userid){
        if ($this->auth < 9){ return false; }
        $q_userid = $this->quote($userid);
        $sql = "delete from users where userid = {$q_userid}";
        $this->db->query($sql);
        $sql = "delete from user_property where userid = {$q_userid}";
        $this->db->query($sql);
        return $userid;
    }

    public function logging(){
        $hiduke = $this->quote(date('Y-m-d'));
        $jikoku = $this->quote(date('H:i:s'));
        $userid = $this->quote($this->userid);
        $ipadrs = $this->quote($_SERVER['REMOTE_ADDR']);
        $url    = $this->quote($_SERVER['REQUEST_URI'].$_SERVER['QUERY_STRING']);
        $referer = $this->quote(''); if (isset($_SERVER['HTTP_REFERER'])){ $referer = $this->quote($_SERVER['HTTP_REFERER']); }
        $sql = <<<_SQL_
insert into user_log (hiduke, jikoku, userid, ipadrs, url, referer)
values ($hiduke, $jikoku, $userid, $ipadrs, $url, $referer)
_SQL_;
        $this->db->query($sql);
        return;
    }

}

/*
-- Adminer 4.7.8 MySQL dump

SET NAMES utf8;
SET time_zone = '+00:00';
SET foreign_key_checks = 0;
SET sql_mode = 'NO_AUTO_VALUE_ON_ZERO';

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `userid` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
  `loginname` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
  `password` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `auth` tinyint(3) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


DROP TABLE IF EXISTS `user_property`;
CREATE TABLE `user_property` (
  `userid` varchar(32) COLLATE utf8_unicode_ci NOT NULL,
  `username` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `mailadrs` varchar(255) COLLATE utf8_unicode_ci NOT NULL DEFAULT '',
  PRIMARY KEY (`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


DROP TABLE IF EXISTS `user_session`;
CREATE TABLE `user_session` (
  `session` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `userid` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  `session_expire` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  PRIMARY KEY (`session`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


-- 2021-03-25 16:30:40
*/
