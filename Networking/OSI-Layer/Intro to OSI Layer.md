 

### **Introduction to the OSI Model**  

The **Open Systems Interconnection (OSI) model** is a conceptual framework used to standardize network communication functions into seven distinct layers. Each layer serves a specific purpose and interacts with adjacent layers to enable seamless data transmission across networks.

---

### **The 7 Layers of the OSI Model**  

1. **Physical Layer ([[Layer-1]])**  
   - Deals with raw bit transmission over physical media (e.g., cables, Wi-Fi).  
   - Defines electrical, mechanical, and procedural aspects (voltage levels, pin layouts).  

1. **Data Link Layer ([[Layer-2]])**  
   - Responsible for node-to-node communication (e.g., MAC addressing in Ethernet).  
   - Error detection/correction (CRC) and framing of data into frames.  

1. **Network Layer ([[Layer-3]])**  
   - Handles logical addressing (IP addresses) and routing packets across networks.  
   - Protocols: IP, ICMP, routers operate here.  

1. **Transport Layer ([[Layer-4]])**  
   - Ensures end-to-end communication reliability (TCP) or speed (UDP).  
   - Manages flow control, error recovery, and segmentation/reassembly.  

1. **Session Layer ([[Layer-5]])**  
   - Establishes, maintains, and terminates sessions between applications.  
   - Examples: NetBIOS, RPC.  

1. **Presentation Layer ([[Layer-6]])**  
   - Translates data formats between applications (encryption/decryption, compression).  
   - Example: SSL/TLS for secure transmission.  

1. **Application Layer ([[Layer-7]])**  
   - User-facing protocols like HTTP(S), FTP, SMTP—directly interacts with software apps.  

---

### **Key Benefits of the OSI Model**  
- Standardizes network communication for interoperability.  
- Simplifies troubleshooting by isolating layer-specific issues.  
- Guides protocol development and network architecture design.



Here’s a structured table summarizing the **OSI Model layers**, their **functions**, **common protocols**, and associated **cyber threats**:  

| **Layer**         | **Name**           | **Function**                                                                 | **Common Protocols**                     | **Common Cyber Threats**                                                                 |
|-------------------|--------------------|-----------------------------------------------------------------------------|------------------------------------------|-----------------------------------------------------------------------------------------|
| **Layer 1**       | Physical           | Transmits raw bits over physical media (cables, Wi-Fi).                     | Ethernet, USB, Bluetooth, DSL           | Cable tampering, signal jamming, RFID cloning.                                          |
| **Layer 2**       | Data Link          | Node-to-node communication (MAC addressing), error detection (CRC).         | Ethernet (MAC), PPP, VLANs               | MAC spoofing, ARP poisoning, VLAN hopping.                                               |
| **Layer 3**       | Network            | Logical addressing (IP), routing packets across networks.                   | IP, ICMP, BGP, OSPF                      | IP spoofing, DDoS (e.g., ICMP floods), route hijacking.                                  |
| **Layer 4**       | Transport          | End-to-end reliability (TCP) or speed (UDP), flow control.                  | TCP, UDP, SCTP                           | SYN floods (TCP), UDP amplification attacks.                                             |
| **Layer 5**       | Session            | Manages sessions between applications (setup/teardown).                     | NetBIOS, RPC                             | Session hijacking, man-in-the-middle (MITM) attacks.                                     |
| **Layer 6**       | Presentation       | Data translation (encryption/compression).                                  | SSL/TLS, JPEG, MPEG                      | SSL stripping, encryption downgrade attacks.                                             |
| **Layer 7**       | Application        | User-facing protocols for software applications.                            | HTTP(S), FTP, SMTP, DNS                  | Phishing (HTTP), SQL injection (web apps), malware delivery via SMTP/FTP.                |

---

### **Key Takeaways**:  
- Each layer has unique vulnerabilities requiring targeted defenses (e.g., firewalls for L3/L4; encryption for L6).  
- Attacks often exploit protocol weaknesses (e.g., ARP spoofing at L2; HTTP-based exploits at L7).  
- Layered security ("defense in depth") aligns with the