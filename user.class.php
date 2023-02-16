<?php
/*
    user.class.php

    version 1.0 - 2016.11.17
    version 2.0   2019. 4. 5 - 2021. 3.23
    version 3.0   2021. 3.25 -
    version 3.0.2 2021.10. 3 -
    version 3.1.0 2022. 7.29 -
    version 3.2   2022.10.17 -
    version 4.0   2022.11.27 - Use PDO::

    Usage:
      $user = new user();
      $user->login(['login'|'admin'|'auth=N']);
---------------------------------------------------------------------*/
class user {


public $userid, $guestid, $auth, $loginname;

function __construct(){
    include __DIR__.'/user.config.php';
    $this->expires_time = $this->config['expires'] + time();

    // DB https://www.php.net/manual/ja/pdo.drivers.php
    switch ($this->config['db_type']){
        case 'mysql':
            $this->db = new PDO('mysql:host='.$this->config['db_host'].';dbname='.$this->config['db_name'], $this->config['db_user'], $this->config['db_pass']);
            break;
        case 'sqlite':
            $this->db = new PDO('sqlite:'.$this->config['db_name']);
            break;
    }
    $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $this->p = array();

    // keep login
    $this->keep_login = $this->config['keep_login'];

    // Delete expired sessions
    $sql = $this->db->prepare('delete from user_session where session_expire < ?');
    $sql->execute([time()]);

    // User session ID stored in COOKIE
    $this->session_u = '';
    if (isset($_COOKIE[$this->config['cookie_u']]) && $_COOKIE[$this->config['cookie_u']]){
        $this->session_u = $_COOKIE[$this->config['cookie_u']];
    }
}


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

    // returned from the login form
    if (isset($_POST['loginname']) && isset($_POST['password'])){
        $sql = $this->db->prepare('select `userid`, `password`, `auth`, `loginname` from users where `loginname` = ?');
        $sql->execute([$_POST['loginname']]);

        if ($row = $sql->fetch(PDO::FETCH_NUM)){
            list($userid, $hashed_password, $auth, $loginname) = $row;
        }
        else {   // 入力した loginname が不正
            $this->logout();
            $this->loginform('Loginname or password is invalid.');   // ログインフォームに移動してエラーメッセージを表示する
        }

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
                $sql = $this->db->prepare('update users set `password` = ? where `userid` = ?');
                $sql->execute([$hashed_password, $this->userid]);
            }
        }

        else {
            $this->logout();
            $this->loginform('Loginname or password is invalid.');
        }

        // keep login
        if (isset($_POST['keep_login']) && $_POST['keep_login']){ $this->keep_login = 1; }

        //
        $this->session_u = $this->make_session(32);
        $sql_sentence = <<<_SQL_
insert into user_session (`session`, `userid`, `session_expire`, `keep_login`)
values (?, ?, ?, ?)
_SQL_;
        $sql = $this->db->prepare($sql_sentence);
        $sql->execute([$this->session_u, $this->userid, $this->expires_time, $this->keep_login]);
    }

    // Check session stored in cookie
    else if ($this->session_u){
        $sql = $this->db->prepare('select userid, keep_login from `user_session` where `session` = ?');
        $sql->execute([$this->session_u]);
        if ($row = $sql->fetch(PDO::FETCH_NUM)){
            list($this->userid, $this->keep_login) = $row;

            $sql = $this->db->prepare('select `auth`, `loginname` from users where `userid` = ?');
            $sql->execute([$this->userid]);
            $row = $sql->fetch(PDO::FETCH_NUM);
            list($this->auth, $this->loginname) = $row;
        }
        else {
            $this->logout();
            $this->loginform('Please login again.');
        }

        // session update
        if ($this->config['update_session']){
            $new_session = $this->make_session(32);
            $sql_sentence = <<<_SQL_
update user_session
set `session` = ?, `session_expire` = ?, `keep_login` = ?
where `session` = ?
_SQL_;
            $sql = $this->db->prepare($sql_sentence);
            $sql->execute([$new_session, $this->expires_time, $this->keep_login, $this->session_u]);
            $this->session_u = $new_session;
        }

    }

    else if (empty($loginparam)){
        return;
    }

    else {
        $this->logout();
        $this->loginform('Please login again.');
    }

    // Check permissions
    // admin
    if ($loginparam == 'admin' && $this->auth < 9){
        $this->logout();
        $this->loginform('Please login with administrator privileges.');
    }
    // Login with restricted privileges
    else if (preg_match("/^auth\=([0-9])$/", $loginparam, $matches) && $this->auth < $matches[1]){
        $this->logout();
        $this->loginform('Not authorized.');
    }

    // set cookie
    if ($this->keep_login){ $expires = $this->expires_time; } else { $expires = ''; }
    setcookie($this->config['cookie_u'], $this->session_u, $this->get_cookie_options($expires));

    // Single login: Delete invalid own sessions
    if (!$this->config['multi_login']){
        $sql = $this->db->prepare('delete from `user_session` where `userid` = ? and `session` != ?');
        $sql->execute([$this->userid, $this->session_u]);
    }

    // get property
    $sql = $this->db->prepare('select * from user_property where `userid` = ? limit 1');
    $sql->execute([$this->userid]);
    $this->p = $sql->fetch(PDO::FETCH_ASSOC);

    return;
}


public function logout(){
    // Delete session
    if (isset($this->session_u) && $this->session_u){
        $sql = $this->db->prepare('delete from user_session where `session` = ?');
        $sql->execute([$this->session_u]);
    }

    // Delete Cookie
    setcookie($this->config['cookie_u'], '', $this->get_cookie_options('delete'));

    //
    $this->session_u = '';
    $this->userid = '';
    $this->auth = 0;
    $this->p = array();

    return;
}


// Issue guest-id
public function guestid(){
    // Delete expired guest ID
    $sql = $this->db->prepare('delete from users where `auth` = 0 and `password` < ?');
    $sql->execute([time()]);

    // Extend guestid expiration time
    if (isset($_COOKIE[$this->config['cookie_g']]) && $_COOKIE[$this->config['cookie_g']]){
        $g = $_COOKIE[$this->config['cookie_g']];
        $sql = $this->db->prepare('update users set `password` = ? where `userid` = ?');
        $sql->execute([$this->expires_time, $g]);
    }
    // issue guestid
    else {
        $e = 1;
        while ($e){
            $g = $this->make_rndstr(32);
            $sql = $this->db->prepare('select userid from users where userid = ?');
            $sql->execute([$g]);
            $e = $sql->fetch(PDO::FETCH_NUM);
        }

        $sql_sentence = <<<_SQL_
insert into users (`userid`, `loginname`, `password`, `auth`)
values (?, ?, ?, 0)
_SQL_;
        $sql = $this->db->prepare($sql_sentence);
        $sql->execute([$g, $g, $this->expires_time, 0]);
    }

    setcookie($this->config['cookie_g'], $g, $this->get_cookie_options($this->expires_time));
    $this->guestid = $g;

    return;
}


// Set options for issuing cookies
private function get_cookie_options($expires = ''){
    $array = array(
        'path' => '/',
        'samesite' => 'lax'
    );
    if ($expires == 'delete'){
        $array['expires'] = time() - 3600 * 24;
    }
    else if ($expires > 0){
        $array['expires'] = $expires;
    }
    return $array;
}


public function logging(){
    return;
}


private function make_session($len){
    $e = 1;
    while ($e){
        $session = $this->make_rndstr($len);
        $sql = $this->db->prepare('select `session` from user_session where `session` = ? limit 1');
        $sql->execute([$session]);
        $e = $sql->fetch(PDO::FETCH_NUM);
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


public function loginform($msg = ''){
    // Start the session if it has not started
    if (session_status() !== PHP_SESSION_ACTIVE){ session_start(); }
    $_SESSION['ref'] = $_SERVER['REQUEST_URI'];
    if ($msg){ $_SESSION['msg'] = $msg; }

    header('Location: '.$this->config['login_url']);
    exit;
}


public function useradd($loginname, $password, $auth=1){
    if ($this->auth < 9){ return false; }
    $e = 1;
    while($e){
        $userid = make_rndstr(32);
        $sql = $this->db->prepare('select userid from users where userid = ?');
        $sql->execute([$userid]);
        $e = $sql->fetch(PDO::FETCH_NUM);
    }
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);
    $sql = $this->db->prepare('insert into users (`userid`, `loginname`, `password`, `auth`) values (?, ?, ?, ?)');
    $sql->execute([$userid, $loginname, $hashed_password, $auth]);

    $sql = $this->db->prepare('insert into user_property (`userid`) values (?)');
    $sql->execute([$userid]);
    return $userid;
}


public function userdel($userid){
    if ($this->auth < 9){ return false; }

    $sql = $this->db->prepare('delete from users where `userid` = ?');
    $sql->execute([$userid]);

    $sql = $this->db->prepare('delete from user_property where `userid` = ?');
    $sql->execute([$userid]);

    $sql = $this->db->prepare('delete from user_session where `userid` = ?');
    $sql->execute([$userid]);

    return $userid;
}


}   // End of class

