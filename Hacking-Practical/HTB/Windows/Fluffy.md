![[Fluffy-01.png]]
### Network Scan
Lets start our scan with the target ip using rustscan:
```bash
rustscan -a 10.10.11.69 -- -sV
```

##### Output
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
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.11.69:139
Open 10.10.11.69:88
Open 10.10.11.69:389
Open 10.10.11.69:445
Open 10.10.11.69:464
Open 10.10.11.69:593
Open 10.10.11.69:636
Open 10.10.11.69:53
Open 10.10.11.69:9389
Open 10.10.11.69:49667
Open 10.10.11.69:49688
Open 10.10.11.69:49689
Open 10.10.11.69:49691
Open 10.10.11.69:49707
Open 10.10.11.69:49713
Open 10.10.11.69:49746
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.11.69
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-30 20:09 UTC
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 20:09
Scanning 10.10.11.69 [4 ports]
Completed Ping Scan at 20:09, 0.18s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 20:09
Completed Parallel DNS resolution of 1 host. at 20:09, 0.11s elapsed
DNS resolution of 1 IPs took 0.11s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 20:09
Scanning 10.10.11.69 [16 ports]
Discovered open port 139/tcp on 10.10.11.69
Discovered open port 49689/tcp on 10.10.11.69
Discovered open port 53/tcp on 10.10.11.69
Discovered open port 445/tcp on 10.10.11.69
Discovered open port 49707/tcp on 10.10.11.69
Discovered open port 593/tcp on 10.10.11.69
Discovered open port 88/tcp on 10.10.11.69
Discovered open port 49667/tcp on 10.10.11.69
Discovered open port 9389/tcp on 10.10.11.69
Discovered open port 49746/tcp on 10.10.11.69
Discovered open port 636/tcp on 10.10.11.69
Discovered open port 389/tcp on 10.10.11.69
Discovered open port 464/tcp on 10.10.11.69
Discovered open port 49688/tcp on 10.10.11.69
Discovered open port 49691/tcp on 10.10.11.69
Discovered open port 49713/tcp on 10.10.11.69
Completed SYN Stealth Scan at 20:09, 0.30s elapsed (16 total ports)
Initiating Service scan at 20:09
Scanning 16 services on 10.10.11.69
Completed Service scan at 20:10, 60.09s elapsed (16 services on 1 host)
NSE: Script scanning 10.10.11.69.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 20:10
Completed NSE at 20:10, 0.01s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 20:10
Completed NSE at 20:10, 0.24s elapsed
Nmap scan report for 10.10.11.69
Host is up, received echo-reply ttl 126 (0.13s latency).
Scanned at 2025-06-30 20:09:50 UTC for 60s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2025-06-30 20:09:57Z)
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49688/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49689/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49707/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49713/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49746/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.16 seconds
           Raw packets sent: 20 (856B) | Rcvd: 17 (732B)

```

We can see few things here worth noting as:
```bash
Domain: fluffy.htb
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```
The host is a domain controller of the domain fluffy.htb so lets add that to /etc/hosts file
```bash
sudo echo "10.10.11.69 fluffy.htb DC01.fluffy.htb" >> /etc/hosts
```

Check using 
```bash
cat /etc/hosts

#Output

127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.18.0.2	kali
10.10.11.69 fluffy.htb DC01.fluffy.htb

```

Also you can do ping for domain resolution
```bash
PING fluffy.htb (10.10.11.69) 56(84) bytes of data.
64 bytes from fluffy.htb (10.10.11.69): icmp_seq=1 ttl=126 time=184 ms
64 bytes from fluffy.htb (10.10.11.69): icmp_seq=2 ttl=126 time=102 ms
64 bytes from fluffy.htb (10.10.11.69): icmp_seq=3 ttl=126 time=120 ms
64 bytes from fluffy.htb (10.10.11.69): icmp_seq=4 ttl=126 time=97.1 ms
64 bytes from fluffy.htb (10.10.11.69): icmp_seq=5 ttl=126 time=164 ms
64 bytes from fluffy.htb (10.10.11.69): icmp_seq=6 ttl=126 time=187 ms
^C
--- fluffy.htb ping statistics ---
6 packets transmitted, 6 received, 0% packet loss, time 5007ms
rtt min/avg/max/mdev = 97.064/142.441/186.935/37.249 ms

```

### Recon
We see that the smb ports are open lets try to list the smb shares on the victim
```bash
smbclient -L \\fluffy.htb
```

##### Output
```bash
smbclient -L \\fluffy.htb
Password for [WORKGROUP\root]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	IT              Disk      
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
```
We can see an unusual `Share` called `IT` but while accessing it it says 
```bash
smbclient //fluffy.htb/IT
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
smb: \> 
```

Now lets go back to the HackTheBox page and check the creds given in the room
Username:
```bash
j.fleischman
```
Password:
```bash
J0elTHEM4n1990
```
Lets use the above to check if we can list the shares
```bash
smbclient -U j.fleischman -P J0elTHEM4n1990 //fluffy.htb/IT
```
