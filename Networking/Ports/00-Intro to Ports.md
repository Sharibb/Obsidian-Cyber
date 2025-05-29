Computer networking ports

 ### **Introduction to Computer Networking Ports**

In computer networking, a **port** is a virtual endpoint for communication within a device. Ports allow different applications or services to share a single physical network connection (via an IP address) while maintaining separate communication channels.

#### **Key Concepts:**
1. **Port Number**  
   - A 16-bit unsigned integer (0 to 65535).  
   - Used by transport layer protocols like **TCP (Transmission Control Protocol)** and **UDP (User Datagram Protocol)**.  

2. **Types of Ports:**  
   - **Well-known ports (0–1023):** Reserved for system services (e.g., HTTP: 80, HTTPS: 443, SSH: 22).  
   - **Registered ports (1024–49151):** Assigned by IANA for specific applications (e.g., MySQL: 3306).  
   - **Dynamic/Private ports (49152–65535):** Used temporarily by client applications.  

3. **How Ports Work:**  
   - When data arrives at a device, the OS checks the port number to determine which application should receive it.  
   - Example: A web server listens on port `80` for HTTP requests, while an email server uses port `25` for SMTP.

4. **Security Considerations:**  
   - Open ports can be exploited if not secured properly (**firewalls** help block unauthorized access).  
   - Tools like `nmap` scan ports to check vulnerabilities.

#### **Why Are Ports Important?**
- Enable multiple services to run on one machine without conflicts.  
- Essential for routing traffic correctly in networks.  

Create a Huge table for all the well knowns ports and protocol used in which layer it works and service used with Work of that specific port

 Here is a comprehensive table of well-known ports (0–1023), including their protocols, OSI layer, associated services, and functions:

---

### **Well-Known Ports (0–1023) Reference Table**  


| **Port** | **Protocol** | **OSI Layer** | **Service**       | **Function / Use Case**                                                                       |
| -------- | ------------ | ------------- | ----------------- | --------------------------------------------------------------------------------------------- |
| 20       | TCP          | Transport     | FTP (Data)        | Transfers file data in FTP connections.                                                       |
| 21       | TCP          | Transport     | FTP (Control)     | Manages FTP commands (e.g., login, directory navigation).                                     |
| 22       | TCP          | Transport     | SSH               | Securely access/manage devices remotely (encrypted).                                          |
| 23       | TCP          | Transport     | Telnet            | Unencrypted remote CLI access (insecure, largely deprecated).                                 |
| 25       | TCP          | Transport     | SMTP              | Sends emails between mail servers.                                                            |
| 53       | UDP/TCP      | Transport     | DNS               | Resolves domain names to IPs (UDP for queries, TCP for zone transfers).                       |
| 67/68    | UDP          | Transport     | DHCP              | Dynamically assigns IP addresses to network devices.                                          |
| 69       | UDP          | Transport     | TFTP              | Lightweight file transfer without authentication (e.g., network booting).                     |
| 80       | TCP          | Transport     | HTTP              | Serves unencrypted web traffic (e.g., websites).                                              |
| 110      | TCP          | Transport     | POP3              | Retrieves emails from a server to a local client (older protocol).                            |
| 123      | UDP          | Transport     | NTP               | Synchronizes time across network devices.                                                     |
| 143      | TCP          | Transport     | IMAP              | Manages emails on a remote server (modern alternative to POP3).                               |
| 161/162  | UDP          | Transport     | SNMP              | Monitors and manages network devices (e.g., routers, switches).                               |
| 389      | TCP/UDP      | Transport     | LDAP              | LDAP                   Authenticates and queries directory services (e.g., Active Directory). |
| 443      | TCP          | Transport     | HTTPS             | Encrypts web traffic (HTTP + SSL/TLS).                                                        |
| 445      | TCP          | Transport     | SMB               | Shares files/printers in Windows networks.                                                    |
| 465      | TCP          | Transport     | SMTPS             | Secure SMTP over SSL/TLS (outdated, now replaced by STARTTLS on port 587).                    |
| 587      | TCP          | Transport     | SMTP (Submission) | Secure email submission with STARTTLS encryption.                                             |
| 636      | TCP/UDP      | Transport     | LDAPS             | Secure LDAP over SSL/TLS.                                                                     |


---



 