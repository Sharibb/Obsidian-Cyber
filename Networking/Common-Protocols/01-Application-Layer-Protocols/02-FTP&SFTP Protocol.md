
### **FTP (File Transfer Protocol)**
FTP is a standard network protocol used to transfer files between a client and a server over a network. It operates on **port 21 (control)** and **port 20 (data)** and transmits data in **plaintext**, including usernames, passwords, and file contents. This makes FTP vulnerable to eavesdropping, man-in-the-middle attacks, and data theft. FTP is commonly used in legacy systems or internal networks where security is less critical.

#### **How FTP Works:**
1. The client connects to the server on port 21 (control connection).
2. Authentication occurs via plaintext credentials.
3. For file transfers, a separate data connection is established (port 20 for active mode or a random port for passive mode).
4. Files are transferred unencrypted.

#### **Disadvantages of FTP:**
- ❌ No encryption (data sent in plaintext).  
- ❌ Requires multiple ports (firewall complications).  
- ❌ Vulnerable to attacks like sniffing and spoofing.  

---

### **SFTP (SSH File Transfer Protocol)**
SFTP is a secure alternative to FTP that runs over the **SSH (Secure Shell) protocol** on **port 22**. Unlike FTP, SFTP encrypts all data—including authentication, commands, and file transfers—making it safe for use over untrusted networks like the internet.

#### **How SFTP Works:**
1. The client establishes an encrypted SSH connection with the server.
2. Authentication can use passwords or SSH keys (more secure).
3. All file operations (upload/download/delete) occur within the encrypted tunnel.
4. Only one port (**22**) is needed, simplifying firewall rules.

#### **Advantages of SFTP:**
- ✅ End-to-end encryption (secure against eavesdropping).  
- ✅ Single-port operation (firewall-friendly).  
- ✅ Supports key-based authentication for stronger security.  

---

### **When to Use Each Protocol?**
| Scenario               | Recommended Protocol |
|------------------------|----------------------|
| Legacy/internal systems | FTP                  |
| Secure external transfers | SFTP               |
| Compliance-sensitive data | SFTP             |

**Best Practice:** Always prefer **SFTP** unless working in a fully trusted environment where encryption isn’t required. Modern applications almost exclusively use SFTP due to its security benefits.


---

### **FTP vs. SFTP: Key Differences**
| Feature               | FTP                          | SFTP                          |
|-----------------------|------------------------------|-------------------------------|
| **Protocol Basis**    | Plaintext (unencrypted)      | Encrypted (SSH-based)         |
| **Port**              | 21 (control), 20 (data)      | 22 (runs over SSH)            |
| **Security**          | No encryption (vulnerable)   | End-to-end encryption         |
| **Authentication**    | Username/password            | SSH keys or passwords         |
| **Firewall Friendly** | Requires multiple ports      | Single port (22)              |
| **Use Case**          | Legacy/internal transfers    | Secure file transfers         |

---

### **Key Takeaways:**
1. **Security**: SFTP encrypts all data, while FTP sends credentials/files in plaintext.
2. **Ports**: FTP uses multiple ports; SFTP tunnels everything over SSH (port 22).
3. **Modern Use**: Prefer SFTP for security; FTP only in trusted/internal networks.
