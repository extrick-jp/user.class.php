<?php
/*
    user.class.php

    version 1.0 - 2016.11.17
    version 2.0 2019. 4. 5 - 2021. 3.23
    version 3.0 2021. 3.25 -
    version 3.0.2 2021.10. 3 -
    version 3.1.0 2022. 7.29 -

    Usage:
      $user = new user();
      $user->login(['login'|'admin'|'auth=N']);
---------------------------------------------------------------------*/
class user {


public $userid, $guestid, $auth, $loginname;

private $config, $db;
private $session_u, $keep_login, $expires_time, $script_name;

function __construct(){
    include __DIR__.'/user.config.php';

    // DB
    $this->db = new mysqli($this->config['db_host'], $this->config['db_user'], $this->config['db_pass'], $this->config['db_name']);

    $this->expires_time = $this->config['expires'] + time();
    $this->script_name = $_SERVER['SCRIPT_NAME'];
    $this->p = array();

    // keep login
    $this->keep_login = $this->config['keep_login'];


    // Delete expired sessions
    $sql = "delete from user_session where session_expire < '".time()."'";
    $this->db->query($sql);

    // User session ID stored in COOKIE
    $this->session_u = '';

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
    $loginstatus = 0;   // when success login, $loginstatus = 1;
    if (isset($_POST['loginname']) && isset($_POST['password'])){
        $q_loginname = $this->quote($_POST['loginname']);
        $sql = "select `userid`, `password`, `auth`, `loginname` from users where `loginname` = {$q_loginname}";
        $rtn = $this->db->query($sql);
        if (!$rtn->num_rows){   // Loginname or password is invalid
            $this->logout();
            $this->loginform('Loginname or password is invalid.');
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
            $this->loginform('Loginname or password is invalid.');
        }

        // keep login
        if (isset($_POST['keep_login']) && $_POST['keep_login']){ $this->keep_login = 1; }
    }

    // Check session stored in cookie
    else if (isset($_COOKIE[$this->config['cookie_u']]) && $_COOKIE[$this->config['cookie_u']]){
        $this->session_u = $_COOKIE[$this->config['cookie_u']];
        $q_session_u = $this->quote($this->session_u);
        $sql = "select `userid`, `keep_login` from `user_session` where `session` = {$q_session_u}";
        $rtn = $this->db->query($sql);
        if ($rtn->num_rows){
            list($this->userid, $this->keep_login) = $rtn->fetch_row();
            $sql = "select `auth`, `loginname` from users where `userid` = '{$this->userid}'";
            $rtn = $this->db->query($sql);
            list($this->auth, $this->loginname) = $rtn->fetch_row();
            $rtn->free();
            $loginstatus++;
        }
        else {
            $this->logout();
            $this->loginform('Please login again.');
        }
    }

    if ($loginparam && !$this->auth){
        $this->logout();
        $this->loginform('Please login again.');
    }

    // Check permissions
    if ($loginstatus){
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
    }

    // Cannot login
    else {
        $this->logout();
        return;
    }

    // logined. change session ID.
    if ($this->auth){
        // new session
        $session_u = $this->make_session(32);
        if ($this->session_u){
            $sql = <<<_SQL_
update user_session
set
    `session` = '{$session_u}',
    `session_expire` = {$this->expires_time},
    `keep_login` = {$this->keep_login}
where `session` = '{$this->session_u}'
_SQL_;
        }
        else {
            $sql = <<<_SQL_
insert into user_session (`session`, `userid`, `session_expire`, `keep_login`)
values ('{$session_u}', '{$this->userid}', {$this->expires_time}, {$this->keep_login})
_SQL_;
        }
        $this->db->query($sql);
        $this->session_u = $session_u;  // change session_u

        // set cookie
        if ($this->keep_login){ $expires = $this->expires_time; } else { $expires = 0; }
        setcookie($this->config['cookie_u'], $this->session_u, $this->get_cookie_options($expires));

        // Single login: Delete invalid own sessions
        if (!$this->config['multi_login']){
            $sql = "delete from `user_session` where `userid`='{$this->userid}' and `session` != '{$this->session_u}'";
            $this->db->query($sql);
        }

        // get property
        $sql = "select * from user_property where `userid` = '{$this->userid}' limit 1";
        $rtn = $this->db->query($sql);
        $this->p = $rtn->fetch_assoc();
        $rtn->free();
    }

    return;
}


public function logout(){
    if (isset($this->session_u) && $this->session_u){
        $sql = "delete from user_session where `session` = '{$this->session_u}'";
        $this->db->query($sql);
    }
    setcookie($this->config['cookie_u'], '', $this->get_cookie_options(0));

    $this->session_u = '';
    $this->userid = '';
    $this->auth = 0;
    $this->p = array();

    return;
}


public function guestid(){
    // Delete expired guest ID
    $sql = "delete from users where `auth` = 0 and `password` < '".time()."'";
    $this->db->query($sql);

    // Extend guestid expiration time
    if (isset($_COOKIE[$this->config['cookie_g']]) && $_COOKIE[$this->config['cookie_g']]){
        $g = $_COOKIE[$this->config['cookie_g']];
        $q_g = $this->quote($g);
        $sql = "update users set `password` = '{$this->expires_time}' where `userid` = {$g}";
    }
    // issue guestid
    else {
        $e = 1;
        while ($e){
            $g = $this->make_rndstr(32);
            $sql = "select userid from users where userid = '{$g}'";
            $rtn = $this->db->query($sql);
            $e = $rtn->num_rows;
            $rtn->free();
        }
        $sql = <<<_SQL_
insert into users (`userid`, `loginname`, `password`, `auth`)
values ('{$g}', '{$g}', '{$this->expires_time}', 0)
_SQL_;
    }
    $this->db->query($sql);
    setcookie($this->config['cookie_g'], $g, $this->get_cookie_options($this->expires_time));
    $this->guestid = $g;

    return;
}


// Set options for issuing cookies
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
    // Start the session if it has not started
    if (session_status() !== PHP_SESSION_ACTIVE){ session_start(); }
    // $_SERVER['SCRIPT_NAME'] = Script that called user.class.php
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
    $sql = "delete from user_session where `userid` = {$q_userid}";
    $this->db->query($sql);
    return $userid;
}


}   // End of class

