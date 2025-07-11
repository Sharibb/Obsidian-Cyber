![[Voleur-00.png]]
### Default Credentials
#### Domain
```COPY
voleur.htb
```
#### Username
```COPY
ryan.naylor
```
#### Password
```COPY
HollowOct31Nyt
```

### Network Scan
#### Rustscan 
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
Scanning ports: The virtual equivalent of knocking on doors.

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.11.76:53
Open 10.10.11.76:88
Open 10.10.11.76:135
Open 10.10.11.76:139
Open 10.10.11.76:389
Open 10.10.11.76:445
Open 10.10.11.76:464
Open 10.10.11.76:593
Open 10.10.11.76:636
Open 10.10.11.76:2222
Open 10.10.11.76:5985
Open 10.10.11.76:9389
Open 10.10.11.76:49664
Open 10.10.11.76:49667
Open 10.10.11.76:51972
Open 10.10.11.76:61606
Open 10.10.11.76:61608
Open 10.10.11.76:61607
Open 10.10.11.76:61634
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.11.76
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-11 23:34 UTC
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 23:34
Scanning 10.10.11.76 [4 ports]
Completed Ping Scan at 23:34, 0.13s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 23:34
Scanning voleur.htb (10.10.11.76) [19 ports]
Discovered open port 135/tcp on 10.10.11.76
Discovered open port 53/tcp on 10.10.11.76
Discovered open port 445/tcp on 10.10.11.76
Discovered open port 51972/tcp on 10.10.11.76
Discovered open port 9389/tcp on 10.10.11.76
Discovered open port 139/tcp on 10.10.11.76
Discovered open port 88/tcp on 10.10.11.76
Discovered open port 2222/tcp on 10.10.11.76
Discovered open port 464/tcp on 10.10.11.76
Discovered open port 49667/tcp on 10.10.11.76
Discovered open port 5985/tcp on 10.10.11.76
Discovered open port 61608/tcp on 10.10.11.76
Discovered open port 49664/tcp on 10.10.11.76
Discovered open port 636/tcp on 10.10.11.76
Discovered open port 61607/tcp on 10.10.11.76
Discovered open port 593/tcp on 10.10.11.76
Discovered open port 389/tcp on 10.10.11.76
Discovered open port 61606/tcp on 10.10.11.76
Discovered open port 61634/tcp on 10.10.11.76
Completed SYN Stealth Scan at 23:34, 0.21s elapsed (19 total ports)
Initiating Service scan at 23:34
Scanning 19 services on voleur.htb (10.10.11.76)
Completed Service scan at 23:35, 62.16s elapsed (19 services on 1 host)
NSE: Script scanning 10.10.11.76.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 23:35
Completed NSE at 23:35, 0.44s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 23:35
Completed NSE at 23:35, 0.38s elapsed
Nmap scan report for voleur.htb (10.10.11.76)
Host is up, received echo-reply ttl 126 (0.094s latency).
Scanned at 2025-07-11 23:34:12 UTC for 63s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2025-07-11 18:41:03Z)
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 126
2222/tcp  open  ssh           syn-ack ttl 126 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
5985/tcp  open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
51972/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
61606/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
61607/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
61608/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
61634/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.54 seconds
           Raw packets sent: 23 (988B) | Rcvd: 20 (864B)

```
### Enumeration
#### SMBmap
