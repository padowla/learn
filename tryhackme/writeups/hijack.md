# Hijack

## Enumeration

```bash
nmap -v -A -p- -Pn -sV hijack.thm -oN nmap
```

```bash
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-13 12:36 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 12:36
Completed NSE at 12:36, 0.00s elapsed
Initiating NSE at 12:36
Completed NSE at 12:36, 0.00s elapsed
Initiating NSE at 12:36
Completed NSE at 12:36, 0.00s elapsed
Initiating SYN Stealth Scan at 12:36
Scanning hijack.thm (10.10.119.217) [65535 ports]
Discovered open port 111/tcp on 10.10.119.217
Discovered open port 22/tcp on 10.10.119.217
Discovered open port 80/tcp on 10.10.119.217
Discovered open port 21/tcp on 10.10.119.217
Discovered open port 45869/tcp on 10.10.119.217
SYN Stealth Scan Timing: About 46.00% done; ETC: 12:37 (0:00:36 remaining)
Discovered open port 2049/tcp on 10.10.119.217
Discovered open port 42681/tcp on 10.10.119.217
Discovered open port 39023/tcp on 10.10.119.217
Discovered open port 56592/tcp on 10.10.119.217
Completed SYN Stealth Scan at 12:37, 83.61s elapsed (65535 total ports)
Initiating Service scan at 12:37
Scanning 9 services on hijack.thm (10.10.119.217)
Completed Service scan at 12:37, 11.57s elapsed (9 services on 1 host)
Initiating OS detection (try #1) against hijack.thm (10.10.119.217)
Initiating Traceroute at 12:37
Completed Traceroute at 12:37, 0.06s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:37
Completed Parallel DNS resolution of 1 host. at 12:37, 0.01s elapsed
NSE: Script scanning 10.10.119.217.
Initiating NSE at 12:37
Completed NSE at 12:37, 3.60s elapsed
Initiating NSE at 12:37
Completed NSE at 12:38, 0.48s elapsed
Initiating NSE at 12:38
Completed NSE at 12:38, 0.00s elapsed
Nmap scan report for hijack.thm (10.10.119.217)
Host is up (0.061s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      vsftpd 3.0.3
22/tcp    open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:ee:e5:23:de:79:6a:8d:63:f0:48:b8:62:d9:d7:ab (RSA)
|   256 42:e9:55:1b:d3:f2:04:b6:43:b2:56:a3:23:46:72:c7 (ECDSA)
|_  256 27:46:f6:54:44:98:43:2a:f0:59:ba:e3:b6:73:d3:90 (ED25519)
80/tcp    open  http     Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Home
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      38019/udp6  mountd
|   100005  1,2,3      46674/tcp6  mountd
|   100005  1,2,3      56592/tcp   mountd
|   100005  1,2,3      59470/udp   mountd
|   100021  1,3,4      32969/tcp6  nlockmgr
|   100021  1,3,4      39502/udp6  nlockmgr
|   100021  1,3,4      42681/tcp   nlockmgr
|   100021  1,3,4      46160/udp   nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp  open  nfs      2-4 (RPC #100003)
39023/tcp open  mountd   1-3 (RPC #100005)
42681/tcp open  nlockmgr 1-4 (RPC #100021)
45869/tcp open  mountd   1-3 (RPC #100005)
56592/tcp open  mountd   1-3 (RPC #100005)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5.4
OS details: Linux 5.4
Uptime guess: 0.001 days (since Wed Mar 13 12:36:57 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   60.63 ms 10.8.0.1
2   61.26 ms hijack.thm (10.10.119.217)

NSE: Script Post-scanning.
Initiating NSE at 12:38
Completed NSE at 12:38, 0.00s elapsed
Initiating NSE at 12:38
Completed NSE at 12:38, 0.00s elapsed
Initiating NSE at 12:38
Completed NSE at 12:38, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.91 seconds
           Raw packets sent: 69231 (3.047MB) | Rcvd: 69005 (2.761MB)

```

