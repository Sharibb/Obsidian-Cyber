


Introduction to **Auxiliary Modules** in Metasploit (non-exploit modules for scanning, enumeration, and information gathering).  

#### **Key Concepts Covered:**  
1. **Purpose of Auxiliary Modules:**  
   - Used for reconnaissance (e.g., port scanning, service fingerprinting).  
   - Information gathering (e.g., SNMP enumeration, HTTP header analysis).  
   - Non-destructive actions (e.g., credential testing, brute-forcing).  

2. **Common Module Categories:**  
   - **Scanners:** `auxiliary/scanner/` (e.g., `portscan/tcp`, `smb/smb_version`).  
   - **Enumeration:** `auxiliary/admin/` (e.g., `mysql/mysql_enum`).  
   - **Fuzzers/DoS:** `auxiliary/fuzzers/`, `auxiliary/dos/` (for testing vulnerabilities).  

3. **Basic Commands:**  
   ```bash
   msf6 > use auxiliary/scanner/portscan/tcp
   msf6 > show options
   msf6 > set RHOSTS 192.168.1.0/24
   msf6 > run
   ```

4. **Examples of Auxiliary Modules:**  
   - `scanner/http/title`: Extract webpage titles from HTTP servers.  
   - `admin/smb/psexec_command`: Execute commands via SMB (no payload).  
   - `scanner/ssh/ssh_version`: Identify SSH versions on targets.  

5. **Output Handling:**  
   - Results often saved to the Metasploit database (`workspace`) or exported to files (`loot`).  


---

### **1. Purpose of Auxiliary Modules**
Auxiliary modules in Metasploit are designed for tasks that **do not involve direct exploitation** (unlike exploit modules). They are primarily used for:
- **Reconnaissance**  
  - Discovering open ports (`auxiliary/scanner/portscan/tcp`).  
  - Identifying running services (`auxiliary/scanner/smb/smb_version`).  
  - Fingerprinting web servers (`scanner/http/http_version`).  

- **Information Gathering**  
  - Enumerating SNMP devices (`scanner/snmp/snmp_enum`).  
  - Extracting HTTP headers (`scanner/http/http_header`).  
  - Brute-forcing credentials (`scanner/ssh/ssh_login`).  

- **Non-Destructive Testing**  
  - Testing weak credentials without exploitation.  
  - Fuzzing applications to detect crashes (`fuzzers/http/http_form_field`).  
  - Simulating Denial-of-Service (DoS) attacks (`dos/tcp/synflood`).  

---

### **2. Common Module Categories**
Auxiliary modules are organized into subdirectories based on functionality:

| Category | Path | Example Modules |
|----------|------|----------------|
| **Scanners** | `auxiliary/scanner/` | `portscan/tcp`, `smb/smb_version`, `ssh/ssh_login` |
| **Admin Utilities** | `auxiliary/admin/` | `mysql/mysql_enum`, `smb/psexec_command` |
| **Fuzzers** | `auxiliary/fuzzers/` | `http/http_form_field`, `ftp/ftp_pre_post` |
| **Denial-of-Service (DoS)** | `auxiliary/dos/` | `tcp/synflood`, `http/apache_range_dos` |

---

### **3. Basic Commands & Workflow**
Here’s a step-by-step breakdown of using an auxiliary module:

#### **(a) Selecting a Module**
```bash
msf6 > use auxiliary/scanner/portscan/tcp
```
- Loads the TCP port scanner module.

#### **(b) Configuring Options**

```bash
msf6 > show options
```
- Displays required (`Required: yes`) and optional parameters.  
- Example output:
  ```
  Module options (auxiliary/scanner/portscan/tcp):

     Name         Current Setting  Required  Description
     ----         ---------------  --------  -----------
     RHOSTS                        yes       Target IP(s) or CIDR range
     PORTS        1-1000           yes       Ports to scan (e.g., 22,80,443)
     THREADS      10               yes       Concurrent threads
  ```

#### **(c) Setting Parameters**  
```bash
msf6 > set RHOSTS 192.168.1.0/24   # Target network
msf6 > set PORTS 80,443,22,3389    # Specific ports 
msf6 > set THREADS 20              # Increase speed (with caution)
```

#### **(d) Executing the Module**  
```bash
msf6 > run   # or `exploit` for some modules
```
- Output example:
  ```
  [+] 192.168.1.10:22 - TCP OPEN (SSH)
  [+] 192.168.1.15:80 - TCP OPEN (HTTP)
  [-] 192.168.1.20:443 - Filtered (No response)
  ```

---

### **4. Advanced Usage Examples**
#### **(a) HTTP Title Scanner**  
Extracts webpage titles from web servers:
```bash
msf6 > use auxiliary/scanner/http/title  
msf6 > set RHOSTS file:/path/to/targets.txt  
msf6 > run   # Outputs titles like "Company Login Portal"
```

#### **(b) SMB Command Execution**  
Runs commands via SMB without payload deployment:
```bash
msf6 > use auxiliary/admin/smb/psexec_command  
msf6 > set RHOSTS 192.168.1.100  
msf6 > set SMBUser admin  
msf6 > set SMBPass password123  
msf6 > set COMMAND "whoami"  
msf6 > run   # Executes `whoami` on the target
```


#### **(c) SSH Version Detection**  
Identifies vulnerable SSH versions (e.g., OpenSSH 7.2p2):  
```bash
msf6 > use auxiliary/scanner/ssh/ssh_version  
msf6 > set RHOSTS 10.0.0.1-50  
msf6 > run  
```
- Output example:  
  ```
  [+] 10.0.0.5:22     - SSH server version: SSH-2.0-OpenSSH_7.2p2 (Ubuntu)  
  [!] 10.0.0.12:22    - Vulnerable to CVE-2018-15473 (OpenSSH user enumeration)  
  ```

---

### **5. Output Handling & Data Management**  
Auxiliary modules integrate with Metasploit's **database** for structured results:  

#### **(a) Saving to Workspace**  
```bash
msf6 > services -S ssh  # Filter all discovered SSH services in the database  
msf6 > hosts -c address,os_name  # List hosts with OS info  
```

#### **(b) Exporting Results**  
- **Loot**: Stores credentials, screenshots, or config files:  
  ```bash
  msf6 > loot  # View captured data  
  ```
- **Reports**: Generate HTML/CSV reports:  
  ```bash
  msf6 > db_export -f xml /path/to/report.xml  
  ```

---

### **Key Takeaways**  
1. **No Exploitation**: Auxiliary modules focus on pre/post-exploitation tasks without payload delivery.  
2. **Flexibility**: Combine scanners (e.g., `smb_version` + `smb_login`) for deeper reconnaissance.  
3. **Resource Efficiency**: Use `THREADS` cautiously to avoid overwhelming targets or detection.  

For further learning, explore modules like:  
- `auxiliary/scanner/http/crawler` (Website crawling).  
- `auxiliary/gather/windows_secrets_dump` (Post-exploitation credential extraction).  

