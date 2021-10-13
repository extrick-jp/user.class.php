<?php
/*
    extrick.jp
    login.php

    2020.11.15 - 2021. 1. 2
    2021.10.13 without reCAPTCHA
-------------------------------------------------------------------------------*/
session_start();
if (isset($_SESSION['ref'])){
    $ref = $_SESSION['ref'];
    unset($_SESSION['ref']);
}
else { $ref = '/'; }

require_once './user.class.php';

?><!DOCTYPE html>

<html>
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="format-detection" content="telephone=no">

<title>Login</title>

</head>
<body>
<form method="post" action="<?php echo $ref; ?>">
    <div>Login ID: <input type="text" name="loginname" /></div>
    <div>Password: <input type="password" name="password" /></div>
    <div><input type="checkbox" name="stay_login" value="1" checked /> ログインしたままにする</div>
    <div><input type="submit" value="LOGIN" /></div>
</form>

</body>
</html>
