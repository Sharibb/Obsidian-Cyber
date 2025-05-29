
# **Port Scanning with Nmap: Brief Overview**  

**Port scanning** is the process of identifying open, closed, or filtered ports on a target system to assess network security. **Nmap (Network Mapper)** is the most popular tool for port scanning due to its versatility and powerful scripting engine.  

---

### **Common Nmap Port Scanning Techniques**  

| **Scan Type**       | **Command**                     | **Description** |
|----------------------|---------------------------------|----------------|
| **TCP SYN Scan**     | `nmap -sS <target>`            | Stealthy scan (half-open), avoids full TCP connection. |
| **TCP Connect Scan** | `nmap -sT <target>`            | Completes full TCP handshake (noisier). |
| **UDP Scan**         | `nmap -sU <target>`            | Scans UDP ports (slower than TCP). |
| **Version Detection**| `nmap -sV <target>`            | Detects service versions running on open ports. |
| **OS Detection**     | `nmap -O <target>`             | Attempts to guess the target OS. |
| **Aggressive Scan**  | `nmap -A <target>`             | Enables OS detection, version detection, and script scanning. |
| **Quick Scan**       | `nmap -T4 -F <target>`         | Fast scan for common ports (top 100). |
| **Full Port Scan**   | `nmap -p- <target>`            | Scans all 65,535 ports (slow but thorough). |

---

### **Additional Useful Flags**
- `-Pn` → Skip host discovery (treat host as online)  
- `--script=<script-name>` → Run NSE scripts (e.g., `--script=vuln`)  
- `-oN/-oX/-oG` → Save output in Normal/XML/Grepable format  
- `--top-ports 1000` → Scan top 1000 most common ports  

---

### **Example Commands**
1. Basic SYN scan:  
   ```bash
   nmap -sS 192.168.1.1
   ```
2. Full port scan with version detection:  
   ```bash
   nmap -p- -sV 192.168.1.1