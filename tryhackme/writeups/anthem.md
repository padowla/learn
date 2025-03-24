---
description: https://tryhackme.com/room/anthem
---

# Anthem

This task involves you, paying attention to details and finding the 'keys to the castle'.

This room is designed for beginners, however, everyone is welcomed to try it out!

Enjoy the Anthem.

In this room, you don't need to brute force any login page. Just your preferred browser and Remote Desktop.

Please give the box up to 5 minutes to boot and configure.

## Enumeration

```bash
nmap -A -p- -v -sC anthem.thm -Pn
```

{% code overflow="wrap" %}
```
Nmap scan report for anthem.thm (10.10.195.74)
Host is up (0.057s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Anthem.com - Welcome to our blog
| http-robots.txt: 4 disallowed entries 
|_/bin/ /config/ /umbraco/ /umbraco_client/
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WIN-LU09299160F
| Issuer: commonName=WIN-LU09299160F
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-24T16:01:28
| Not valid after:  2024-07-25T16:01:28
| MD5:   5220:dea9:3d1f:723c:ac00:2e5c:c137:d1ed
|_SHA-1: b965:4879:418e:3399:dd81:7de2:133c:0f12:0d84:c602
|_ssl-date: 2024-01-25T16:09:09+00:00; -2s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WIN-LU09299160F
|   NetBIOS_Domain_Name: WIN-LU09299160F
|   NetBIOS_Computer_Name: WIN-LU09299160F
|   DNS_Domain_Name: WIN-LU09299160F
|   DNS_Computer_Name: WIN-LU09299160F
|   Product_Version: 10.0.17763
|_  System_Time: 2024-01-25T16:09:04+00:00
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=252 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -2s, deviation: 0s, median: -3s

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   56.24 ms 10.18.0.1
2   57.77 ms anthem.thm (10.10.195.74)

NSE: Script Post-scanning.
Initiating NSE at 11:09
Completed NSE at 11:09, 0.00s elapsed
Initiating NSE at 11:09
Completed NSE at 11:09, 0.00s elapsed
Initiating NSE at 11:09
Completed NSE at 11:09, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 130.19 seconds
           Raw packets sent: 131245 (5.780MB) | Rcvd: 120 (5.376KB)

```
{% endcode %}

The poem in this blog post:

<figure><img src="../../.gitbook/assets/image (214).png" alt=""><figcaption></figcaption></figure>

is a reference to the real name of IT Administrator:

<figure><img src="../../.gitbook/assets/image (215).png" alt=""><figcaption></figcaption></figure>

Visiting the "We are hiring" page we find some useful information about a possible pattern for internal username and email company:

<figure><img src="../../.gitbook/assets/image (216).png" alt=""><figcaption></figcaption></figure>

If we try to request sitemap.xml we obtain a strange error:

<figure><img src="../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

Going to endpoint /umbraco we obtain this one:

<figure><img src="../../.gitbook/assets/image (218).png" alt=""><figcaption></figcaption></figure>

Umbraco is an open-source content management system (CMS) platform for publishing content on the World Wide Web and intranets. It is written in C# and deployed on Microsoft based infrastructure.

Try logging in using these credentials seems to work: `SG@anthem.com UmbracoIsTheBest!`

<figure><img src="../../.gitbook/assets/image (219).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (220).png" alt=""><figcaption></figcaption></figure>

Searching in the source code of different web pages we can find the flags:

<figure><img src="../../.gitbook/assets/image (222).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (223).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (224).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

Try to RDPing using stolen credentials we can find on Desktop the user flag:

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

### Info

* WIN-LU09299160F
*   robots.txt:\
    \


    <figure><img src="../../.gitbook/assets/image (227).png" alt=""><figcaption></figcaption></figure>
* Possible password: `UmbracoIsTheBest!`
* Possible usernames:
  * `Jane Doe`, `JD@anthem.com`
  * `James Orchard Halliwell`, `JOH@anthem.com`
  * `Solomon Grundy`, `SG@anthem.com`<- Administrator account
* domain of website: anthem.com
* IIS 10.0 Windows Server

## Privilege Escalation

The hint on the the final task says the admin password is hidden somewhere. To see all hidden files and folders, I followed these steps first.

1. Open File Explorer from the taskbar.
2. Select the View tab. Go to Options, and select the Change folder and search options.
3. Select the View tab. In Advanced settings, select Show hidden files, folders, and drives.
4. Select Ok.

Now I could see a hidden folder named ‘backup’ in the C drive.

Inside the folder there’s a file named ‘restore’ which couldn’t be opened due to permission error.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*68JHfGBx8eEQx-hwrxfCbw.png" alt="" height="372" width="700"><figcaption></figcaption></figure>

But the funny thing is: I could alter the file permission from file properties.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*fvWbbd7qKM23rTrLTvVCNQ.png" alt="" height="372" width="700"><figcaption></figcaption></figure>

Go to Properties>Security>Edit>Add and add your own username. Once added, click Ok. Then allow Full Control from the checkbox.

Now open the file and there is the password of Administrator.

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*8S86Ryad_VU-1nfeIpluuw.png" alt="" height="372" width="700"><figcaption></figcaption></figure>

With this password, connect to the host via remote desktop. There you’ll get your root flag.

<figure><img src="../../.gitbook/assets/image (212).png" alt=""><figcaption></figcaption></figure>
