

The **SSH (Secure Shell) protocol** is a cryptographic network protocol used for secure remote login, command execution, and data communication over an unsecured network. Below is a structured breakdown of key aspects of SSH:

### **1. Overview**
- **Purpose**: Provides encrypted communication between two untrusted hosts over an insecure network.
- **Common Uses**:
  - Remote server administration (`ssh user@host`).
  - Secure file transfer (`scp`, `sftp`).
  - Port forwarding/tunneling.

---

### **2. Key Features**
- **Encryption**: Uses symmetric encryption (e.g., AES), asymmetric encryption (RSA, ECDSA), and hashing (SHA-2) to secure data.
- **Authentication Methods**:
  - Password-based (less secure).
  - Public-key authentication (more secure, uses key pairs).
  - Host-based authentication.
- **Port**: Default port `22`.

---

### **3. SSH Components**
1. **SSH Client**: Initiates the connection (e.g., OpenSSH, PuTTY).
2. **SSH Server**: Listens for connections (`sshd` daemon).
3. **Key Pairs**:
   - Public key: Stored on the server (`~/.ssh/authorized_keys`).
   - Private key: Kept securely on the client.

---

### **4. Basic Commands**
| Command | Description |
|---------|-------------|
| `ssh user@host` | Connects to a remote host. |
| `ssh-keygen` | Generates a new SSH key pair. |
| `ssh-copy-id user@host` | Copies the public key to a server for password-less login. |
| `scp file user@host:/path` | Securely copies files over SSH. |

---

### **5. Security Best Practices**
- Disable root login via SSH (`PermitRootLogin no` in `/etc/ssh/sshd_config`).
- Use key-based authentication instead of passwords.
- Change the default SSH port to reduce brute-force attacks.
- Keep software updated to patch vulnerabilities.

---

### **6. Common SSH Protocols**
- **SSH-1** (Legacy, insecure; deprecated due to vulnerabilities).
- **SSH-2** (Current standard; supports stronger encryption and integrity checks).

