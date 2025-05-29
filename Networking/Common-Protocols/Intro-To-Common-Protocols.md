Common protocols used in networking 

Here’s an introduction to common networking protocols, categorized by their primary use cases:

---

### **1. Application Layer Protocols**  
(Enable communication between applications and services.)  
- **HTTP/HTTPS** (Hypertext Transfer Protocol/Secure):  
  - HTTP: Used for unencrypted web traffic (port 80).  
  - HTTPS: Encrypted with TLS/SSL (port 443).  
- **FTP/SFTP** (File Transfer Protocol/Secure FTP):  
  - FTP: Transfers files (port 20/21, unencrypted).  
  - SFTP: Secure file transfer over SSH (port 22).  
- **SMTP** (Simple Mail Transfer Protocol): Sends emails (port 25 or 587 with TLS).  
- **POP3/IMAP**: Retrieve emails from servers (POP3: port 110; IMAP: port 143).  
- **DNS** (Domain Name System): Translates domain names to IP addresses (port 53).  

---

### **2. Transport Layer Protocols**  
(Ensure end-to-end communication and reliability.)  
- **TCP** (Transmission Control Protocol):  
  - Connection-oriented, reliable, ensures data delivery (e.g., HTTP, SSH).  
- **UDP** (User Datagram Protocol):  
  - Connectionless, low-latency but unreliable (e.g., VoIP, DNS queries).  

---

### **3. Network Layer Protocols**  
(Handle routing and logical addressing.)  
- **IP** (Internet Protocol): Routes packets using IP addresses (IPv4/IPv6).  
- **ICMP** (Internet Control Message Protocol): Diagnostics and errors (e.g., `ping` uses ICMP Echo Request/Reply).  

---

### **4. Security Protocols**  
(Encrypt and authenticate data.)  
- **TLS/SSL** (Transport Layer Security/Secure Sockets Layer): Encrypts web traffic (HTTPS, FTPS).  
- **SSH** (Secure Shell): Encrypted remote access/command-line sessions (port 22).  

---

### **5. Local Network Protocols**  
(Facilitate communication within a local network.)  
- **DHCP** (Dynamic Host Configuration Protocol): Assigns IP addresses dynamically.   
- **ARP** (Address Resolution Protocol): Maps IP addresses to MAC addresses.  

---

### **6. Session Layer Protocols**  
(Manage and control sessions between applications.)  
- **RPC** (Remote Procedure Call): Allows a program to execute code on another device.  
- **NetBIOS**: Facilitates communication within a local network (often used with SMB).  

---

### **7. Presentation Layer Protocols**  
(Handle data formatting, encryption, and compression.)  
- **SSL/TLS**: Also operates here for encryption (though primarily in the Transport Layer).  
- **MIME** (Multipurpose Internet Mail Extensions): Formats non-text email attachments (e.g., images, documents).  

---

### **8. Miscellaneous Protocols**  
(Other widely used protocols.)  
- **SNMP** (Simple Network Management Protocol): Monitors and manages network devices (port 161/162).  
- **NTP** (Network Time Protocol): Synchronizes clocks across devices (port 123).  

---

### **9. Wireless & IoT Protocols**  
(For wireless communication and IoT devices.)  
- **Wi-Fi (802.11)**: Standard for wireless LANs.  
- **Bluetooth**: Short-range wireless communication.  
- **MQTT** (Message Queuing Telemetry Transport): Lightweight protocol for IoT messaging.  

---

#### Key Takeaways:  
1. Protocols are organized by **[[Intro to OSI Layer|OSI]]** model layers but often span multiple layers in practice.  
2. Security-focused protocols (TLS, SSH, SFTP) are critical for protecting data in transit.  
3. UDP prioritizes speed over reliability, while TCP ensures accurate delivery.  
