


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

explain further


---

