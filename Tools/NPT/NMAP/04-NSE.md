Discuss briefly about nmaps NSE and cheat sheet 


### **Nmap Scripting Engine (NSE) and Cheat Sheet**

#### **What is NSE?**
The **Nmap Scripting Engine (NSE)** is a powerful feature in Nmap that allows users to automate and extend Nmap's capabilities using Lua scripts. These scripts can perform tasks like:
- Vulnerability detection
- Service enumeration
- Exploitation checks
- Network discovery
- Data extraction

#### **Types of NSE Scripts**
1. **Discovery** – Finds hosts and services (`broadcast-dhcp-discover`).
2. **Version Detection** – Enhances service version detection (`http-server-header`).
3. **Vulnerability Scanning** – Checks for known vulnerabilities (`http-vuln-cve2017-5638`).
4. **Exploitation** – Tests exploitability (`smb-vuln-ms17-010`).
5. **Brute Force** – Performs login attacks (`ftp-brute`, `ssh-brute`).

---

### **NSE Cheat Sheet**

#### **Basic Usage**
```sh
nmap --script=<script-name> <target>
```
Example:
```sh
nmap --script=http-title scanme.nmap.org
```

#### **Run Multiple Scripts**
```sh
nmap --script=<script1>,<script2> <target>
```

#### **Run Script Categories**
```sh
nmap --script "vuln or safe" <target>
```
Common categories: `vuln`, `exploit`, `discovery`, `brute`.

#### **Update NSE Scripts**
```sh
nmap --script-updatedb
```

#### **List Available Scripts**
```sh
ls /usr/share/nmap/scripts/
```
or  
```sh
nmap --script-help "*smb*"
```

---

### **Commonly Used NSE Scripts**  
| Category       | Example Scripts                     | Description |
|----------------|-------------------------------------|-------------|
| **Discovery**  | `dns-brute`, `snmp-info`            | Enumerates hosts/services (e.g., DNS subdomains, SNMP device info). |
| **Vulnerability** | `http-vuln-cve2021-44228` (Log4j), `http-vuln-cve2017-5638` | Checks for critical CVEs in services (e.g., Log4j, Apache Struts). |
| **Brute Force**  | `ssh-brute`, `mysql-brute`, `ftp-brute` | Performs password attacks against services. |
| **Exploitation**  | `smb-vuln-ms17-010` (EternalBlue)   | Tests exploitability of vulnerabilities (e.g., SMB exploits). |
| **Version Detection** | `http-server-header`, `ssl-cert`    | Enhances service fingerprinting (e.g., HTTP headers, SSL certs). |
| **Safe Scripts**   | `http-robots.txt`, `whois-ip`       | Non-intrusive scripts for reconnaissance. |

---

### **Brief Discussion on NSE and Cheat Sheet**  
1. **NSE Overview**:  
   - The Nmap Scripting Engine (**NSE**) extends Nmap’s functionality through Lua scripts, enabling automated tasks like vulnerability scanning, brute-forcing, and network discovery.  
   - Scripts are categorized by purpose (e.g., `vuln`, `exploit`, `discovery`) and can be combined for comprehensive scans.  

2. **Cheat Sheet Utility**:  
   - The cheat sheet provides quick commands for running scripts (`--script=<name>`), updating scripts (`--script-updatedb`), and filtering by categories (`vuln or safe`).  
   - Example use cases:  
     ```sh
     # Scan for vulnerabilities in a web server:
     nmap --script "http-vuln*" <target>
     # Brute-force SSH credentials:
     nmap --script ssh-brute --script-args userdb=users.txt
```

### **Advanced NSE Usage**  
#### **Script Arguments**  
Pass custom arguments to scripts:  
```sh
nmap --script <script> --script-args <key>=<value>  
```
Example (brute-force with a custom user list):  
```sh
nmap --script ssh-brute --script-args userdb=users.txt,passdb=/path/to/passwords.txt <target>
```

#### **Debugging Scripts**  
Enable debugging to troubleshoot script behavior:  
```sh
nmap --script <script> -d3  # Level 3 verbosity
```

#### **Aggressive Scanning**  
Combine NSE with aggressive mode (`-A`) for OS/version detection:  
```sh
nmap -A --script "vuln and safe" <target>
```

---

### **Security Considerations**  
1. **Legal/Ethical Use**: Always obtain permission before running NSE scripts (e.g., brute-forcing).  
2. **Network Impact**: Some scripts (e.g., `smb-brute`) may trigger alarms or disrupt services.  

---

### **References**  
- [Official NSE Documentation](https://nmap.org

