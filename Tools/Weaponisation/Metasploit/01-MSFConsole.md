Explain briefly and create a cheat sheet table for commands


### **MSFConsole Cheat Sheet**  
**Metasploit Framework (MSF)** is a powerful penetration testing tool, and `msfconsole` is its primary command-line interface. Below is a brief explanation and a cheat sheet of essential commands.

---

### **Brief Explanation**  
`msfconsole` provides an interactive environment to:  
- Load & manage exploits, payloads, and auxiliary modules.  
- Configure targets, set options, and execute attacks.  
- Manage sessions (e.g., Meterpreter shells).  

---

### **Cheat Sheet Table**  

| **Category**       | **Command**                          | **Description**                                      |
|--------------------|-------------------------------------|----------------------------------------------------|
| **General**        | `help`                              | Show all available commands.                      |
|                    | `banner`                            | Display a random Metasploit banner.               |
|                    | `version`                           | Show Metasploit version.                          |
|                    | `exit` / `quit`                     | Exit `msfconsole`.                                |
| **Modules**        | `search [keyword]`                  | Search for modules (exploits, payloads, etc.).   |
|                    | `use [module_path]`                 | Load a module (e.g., `use exploit/windows/smb/ms17_010_eternalblue`). |
|                    | `show options`                      | Display configurable options for the current module. |
|                    | `show payloads`                     | List compatible payloads for the current exploit. |
| **Exploitation**   | `set RHOSTS [IP]`                   | Set target IP(s).                                 |
|                    | `set LHOST [IP]`                    | Set local listener IP (for reverse shells).       |
|                    | `set LPORT [port]`                  | Set local listener port.                         |
|                    | `run` / `exploit`                   | Execute the loaded module.                        |
| **Sessions**       | `sessions -l`                       | List active sessions.                             |
|                    | `sessions -i [ID]`                  | Interact with a session (e.g., Meterpreter).      |
|                    ｜　`sessions -k [ID] ｜ Kill a session． ｜
｜　Payload Generation ｜　msfvenom -p [

continue the above table
