Explain briefly NMAP and its basic uses

 **NMAP (Network Mapper)** is a powerful open-source tool used for **network discovery, security scanning, and vulnerability assessment**. It helps administrators and security professionals analyze networks by identifying active hosts, open ports, services, and potential vulnerabilities.

### **Basic Uses of NMAP:**
1. **Host Discovery** – Detects live devices on a network (`-sn` flag).  
2. **Port Scanning** – Identifies open ports and services (`-sS`, `-sT`).  
3. **OS Detection** – Guesses the operating system of a target (`-O`).  
4. **Service Version Detection** – Determines software versions running on ports (`-sV`).  
5. **Vulnerability Scanning** – Checks for known security flaws (using scripts like `--script vuln`).  
6. **Firewall Evasion** – Uses stealth techniques to bypass security measures (`-f`, `--mtu`).  

Example command:  
```sh
nmap -sS -A 192.168.1.1
```
(Performs a SYN scan with OS & version detection.)

NMAP is widely used in penetration testing, network audits, and cybersecurity assessments. 🚀


