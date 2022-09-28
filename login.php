<?php
/*
    login.php
    for user.class.php 3.1.x

    extrick.jp
-------------------------------------------------------------------------------*/
session_start();
if (isset($_SESSION['ref'])){
    $ref = $_SESSION['ref'];
    unset($_SESSION['ref']);
}
else { $ref = '/'; }

if (isset($_SESSION['msg'])){
    $msg = '<div class="message">'.$_SESSION['msg'].'</div>';
    unset($_SESSION['msg']);
}
else { $msg = ''; }

?><!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="format-detection" content="telephone=no">

<title>Login</title>

</head>
<body>
<?php echo $msg; ?>
<form method="post" action="<?php echo $ref; ?>">
    <div>Login ID: <input type="text" name="loginname" /></div>
    <div>Password: <input type="password" name="password" /></div>
    <div><input type="checkbox" name="keep_login" value="1" checked />: Keep login</div>
    <div><input type="submit" value="LOGIN!" /></div>
</form>

</body>
</html>
