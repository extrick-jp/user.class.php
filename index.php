<?php
/*
    login test
-------------------------------------------------------------------------------*/
ini_set('display_errors', 1);
require_once './user.class.php';

$user = new user();
$user->login('admin');

print <<<_END_
<!DOCTYPE html>

<html>
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="format-detection" content="telephone=no">
<title>user.class.php test</title>
</head>
<body>\n
_END_;

if ($user->userid){
    print '<h1>Hello!</h1>';
}
else {
    print '<h1>Please login.</h1>';
}

print <<<_END_
<div><a href="?logout">LOGOUT</a></div>
<div>
GUEST:{$_COOKIE['gt']}<br />
USER: {$user->userid}<br/>
<hr />
<pre>Property:
_END_;
print_r($user->p);
print <<<_END_
</pre>\n
_END_;

if ($user->userid && $user->auth > 0){
    $db = new mysqli('DB_HOST', 'DB_USER', 'DB_PASS', 'DB_NAME');

    $sql = "select * from users where userid = '{$user->userid}'";
    $rtn = $db->query($sql);
    $row_users = $rtn->fetch_assoc();
    $rtn->free();

    $sql = "select * from user_session where userid = '{$user->userid}'";
    $rtn = $db->query($sql);
    $row_session = $rtn->fetch_all();
    $rtn->free();

    print <<<_END_
<hr />
Database:<br />
<pre>Users:
_END_;
    print_r($row_users);
    print <<<_END_
</pre>
<pre>Sessions:\n
_END_;
    foreach ($row_session as $session){
        print_r($session);
    }
    print <<<_END_
</pre>\n
_END_;
}

print <<<_END_
</body>
</html>
_END_;
