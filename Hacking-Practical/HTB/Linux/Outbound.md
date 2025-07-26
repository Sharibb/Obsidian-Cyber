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
sudo echo "10.10.11.17 outbound.htb mail.outbound.htb" > /etc/hosts
```

### WebApp Enumeration(Manual Approach)

| ![[Outbound-01.png]]  |
|:--:|
*image_caption*
Its a RoundCube 