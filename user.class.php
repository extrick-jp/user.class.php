<?php
/*
    user.class.php
    (c) Extrick LLC.

    version 1.0 - 2016.11.17
    version 2.0 2019. 4. 5 - 2021. 3.23
    version 3.0 2021. 3.25 -
    version 3.0.2 2021.10. 3 -
    version 3.1.0 2022. 7.29 -

    Usage:
      $user = new user();
      $user->login(['login'|'admin'|'auth=N'|'guest']);
---------------------------------------------------------------------*/
class user {


public $userid, $guestid, $auth, $loginname;

private $session_u, $keep_login;

private $config, $db;
private $expires_time, $expires_date;
private $script_name;

function __construct(){
    include __DIR__.'/user.config.php';

    $this->expires_time = $this->config['expires'] + time();
    $this->expires_date = date('Y-m-d H:i:s', $this->expires_time);

    // DB
    $this->db = new mysqli($this->config['db_host'], $this->config['db_user'], $this->config['db_pass'], $this->config['db_name']);

    $this->script_name = $_SERVER['SCRIPT_NAME'];
    $this->p = array();

    //
    $this->keep_login = $this->config['keep_login'];

    // guest id
    // 古い guestid を削除する
    $sql = "delete from users where `auth` = 0 and `password` < '".date('Y-m-d H:i:s')."'";
    $this->db->query($sql);

    // guestid の有効期限を延長する
    if (isset($_COOKIE[$this->config['cookie_g']]) && $_COOKIE[$this->config['cookie_g']]){
        $g = $_COOKIE[$this->config['cookie_g']];
        $q_g = $this->quote($g);
        $sql = "update users set `password` = '{$this->expires_date}' where `userid` = {$g}";
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
        $sql = "insert into users (`userid`, `password`, `auth`) values ('{$g}', '{$this->expires_date}', 0)";
    }
    $this->db->query($sql);
    setcookie($this->config['cookie_g'], $g, $this->get_cookie_options($this->expires_time));
    $this->guestid = $g;

    // 期限の切れたsessionは削除する
    $sql = "delete from user_session where session_expire < '".date('Y-m-d H:i:s')."'";
    $this->db->query($sql);

    // COOKIEに保存されているユーザーセッションIDを取得する
    $this->session_u = '';
    if (isset($_COOKIE[$this->config['cookie_u']]) && $_COOKIE[$this->config['cookie_u']]){
        $sql = "select userid from user_session where session = '{$_COOKIE[$this->config['cookie_u']]}'";
        $rtn = $this->db->query($sql);
        if ($rtn->num_rows){
            $this->session_u = $_COOKIE[$this->config['cookie_u']];
        }
        $rtn->free();
    }
}

// ログイン
public function login(){
    $loginparam = '';
    if (func_num_args()){ $loginparam = func_get_arg(0); }

    if (isset($_SERVER['QUERY_STRING']) && $_SERVER['QUERY_STRING']){
        $array_query = explode('&', $_SERVER['QUERY_STRING']);
        foreach ($array_query as $query){
            if ($query == 'logout' ){
                $this->logout();
                header('Location: '.$this->config['logout_url']);   // ログアウト後の遷移先
                exit;
            }
        }
    }

    // loginformからの戻り
    $loginstatus = 0;   // when success login, $loginstatus = 1;
    if (isset($_POST['loginname']) && isset($_POST['password'])){
        $q_loginname = $this->quote($_POST['loginname']);
        $sql = "select `userid`, `password`, `auth`, `loginname` from users where `loginname` = {$q_loginname}";
        $rtn = $this->db->query($sql);
        if (!$rtn->num_rows){   // 入力した loginname が不正
            $this->logout();
            $this->loginform('ログインIDまたはパスワードが違います。');   // ログインフォームに移動してエラーメッセージを表示する
        }

        list($userid, $hashed_password, $auth, $loginname) = $rtn->fetch_row();
        $rtn->free();

        /*
            $hashed_password = password_hash($_POST['password'], PASSWORD_BCRYPT);
        */
        if (password_verify($_POST['password'], $hashed_password) || $hashed_password == md5($_POST['password'])){
            $this->userid = $userid;
            $this->auth = $auth;
            $this->loginname = $loginname;

            // md5 -> bcrypt
            if ($hashed_password == md5($_POST['password'])){
                $hashed_password = password_hash($_POST['password'], PASSWORD_BCRYPT);
                $sql = "update users set `password` = '{$hashed_password}' where `userid` = '{$this->userid}'";
                $this->db->query($sql);
            }
            $loginstatus++;
        }
        else {
            $this->logout();
            $this->loginform('ログインIDまたはパスワードが違います。');
        }
    }

    // cookieに保存してあるsessionをチェックする
    else if ($this->session_u){
        $q_session_u = $this->quote($this->session_u);

        $sql = "select userid from `user_session` where `session` = {$q_session_u}";
        $rtn = $this->db->query($sql);
        if ($rtn->num_rows){
            list($this->userid) = $rtn->fetch_row();
            $sql = "select `auth`, `loginname` from users where `userid` = '{$this->userid}'";
            $rtn = $this->db->query($sql);
            list($this->auth, $this->loginname) = $rtn->fetch_row();
            $rtn->free();
            $loginstatus++;
        }
        else {
            $this->logout();
            $this->loginform('ログインし直してください');
        }
    }

    // ユーザーIDでログインできていない場合に、userid <- guestid
    if (!$this->userid){
        $this->userid = $this->guestid;
        $this->auth = 0;
        $this->p = array();
        $loginstatus++;
    }

    // guest を除く、ユーザーログイン
    if ($loginparam == 'login' && !$this->auth){
        $this->logout();
        $this->loginform('ログインしてください');
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
    }

    // ここまでの処理でログインできていない
    else {
        $this->logout();
        return;
    }

    // success login
    if ($this->auth){
        // session update
        $this->upd_session();
        // get property
        $sql = "select * from user_property where `userid` = '{$this->userid}' limit 1";
        $rtn = $this->db->query($sql);
        $this->p = $rtn->fetch_assoc();
        $rtn->free();
    }

    return;
}

//
private function upd_session(){
    if ($this->session_u){
        $sql = "update user_session set `session_expire` = '{$this->expires_date}' where `session` = '{$this->session_u}'";
    }
    else {
        $this->session_u = $this->make_session(32);
        $sql = "insert into user_session (`session`, `session_expire`, `userid`) values ('{$this->session_u}', '{$this->expires_date}', '{$this->userid}')";
    }
    $this->db->query($sql);
    setcookie($this->config['cookie_u'], $this->session_u, $this->get_cookie_options($this->expires_time));

    // シングルログイン： 無効な自分のセッションを削除する
    if (!$this->config['multi_login']){
        $sql = "delete from `user_session` where `userid`='{$this->userid}' and `session` != '{$this->session_u}'";
        $this->db->query($sql);
    }

    return;
}

public function logout(){
    // セッションを削除
    if (isset($this->session_u) && $this->session_u){
        $sql = "delete from user_session where `session` = '{$this->session_u}'";
        $this->db->query($sql);
    }

    // COOKIEを削除
    setcookie($this->config['cookie_u'], '', $this->get_cookie_options(0));

    //
    $this->session_u = '';
    $this->userid = '';
    $this->auth = 0;
    $this->p = array();

    return;
}

private function get_cookie_options($expires){
    return array(        // COOKIE Options
        'expires' => $expires,
        'path' => '/',
        'samesite' => 'lax'
    );
}

public function logging(){
    return;
}

private function make_session($len){
    $e = 1;
    while ($e){
        $session = $this->make_rndstr($len);
        $rtn = $this->db->query("select `session` from user_session where `session` = '{$session}' limit 1");
        $e = $rtn->num_rows;
        $rtn->free();
    }
    return $session;
}

private function make_rndstr($len){
    $seedstr = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $randmax = strlen($seedstr) - 1;
    $rndstr = '';
    for ($i = 1; $i <= $len; $i++){ $rndstr .= substr($seedstr, mt_rand(0, $randmax), 1); }
    return $rndstr;
}

private function quote($val){
    return "'" . $this->db->real_escape_string($val) . "'";
}

public function loginform($msg = ''){
    // セッションがスタートしていなかったらスタートする
    if (session_status() !== PHP_SESSION_ACTIVE){ session_start(); }
    // $_SERVER['SCRIPT_NAME'] -> user.class.php を呼び出したスクリプト
    $_SESSION['ref'] = $this->script_name;
    if ($msg){ $_SESSION['msg'] = $msg; }

    header('Location: '.$this->config['login_url']);
    exit;
}

public function useradd($loginname, $password, $auth=1){
    if ($this->auth < 9){ return false; }
    $e = 1;
    while($e){
        $userid = make_rndstr(32);
        $sql = "select userid from users where userid = '{$userid}'";
        $rtn = $this->db->query($sql);
        $e = $rtn->num_rows();
        $rtn->free();
    }
    $q_loginname = $this->quote($loginname);
    $q_password = $this->quote(password_hash($password, PASSWORD_BCRYPT));
    $sql = "insert into users (`userid`, `loginname`, `password`, `auth`) values ('{$userid}', {$q_loginname}, {$q_password}, {$auth})";
    $this->db->query($sql);
    $sql = "insert into user_property (`userid`) values ('{$userid}')";
    $this->db->query($sql);
    return $userid;
}

public function userdel($userid){
    if ($this->auth < 9){ return false; }
    $q_userid = $this->quote($userid);
    $sql = "delete from users where `userid` = {$q_userid}";
    $this->db->query($sql);
    $sql = "delete from user_property where `userid` = {$q_userid}";
    $this->db->query($sql);
    return $userid;
}


}   // End of class

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
