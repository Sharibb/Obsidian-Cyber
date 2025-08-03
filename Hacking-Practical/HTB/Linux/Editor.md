![[Editor-00.png]]

Add `editor.htb` to /etc/hosts

```bash
echo "10.10.11.80 editor.htb" >> /etc/hosts
```

## Network Scan

### Rustscan

```bash
rustscan -a editor.htb > rustscan.txt
```

Output

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
TreadStone was here 🚀

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.11.80:22
Open 10.10.11.80:80
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-03 12:49 UTC
Initiating Ping Scan at 12:49
Scanning 10.10.11.80 [4 ports]
Completed Ping Scan at 12:49, 0.36s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 12:49
Scanning editor.htb (10.10.11.80) [2 ports]
Discovered open port 80/tcp on 10.10.11.80
Discovered open port 22/tcp on 10.10.11.80
Completed SYN Stealth Scan at 12:49, 0.69s elapsed (2 total ports)
Nmap scan report for editor.htb (10.10.11.80)
Host is up, received echo-reply ttl 62 (0.39s latency).
Scanned at 2025-08-03 12:49:44 UTC for 1s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 62
80/tcp open  http    syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.19 seconds
           Raw packets sent: 6 (240B) | Rcvd: 11 (436B)
```

We got only `ssh` and `http` port open so lets head straight to web enumeration

## Web Enumeration

Upon opening the website in the browser we can see that it is a code editor.

![[Editor-01.png]]
Nothing much on the website only 2 binaries for windows and debian lets Download and inspect them.

