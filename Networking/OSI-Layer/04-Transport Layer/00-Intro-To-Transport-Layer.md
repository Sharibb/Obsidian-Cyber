
### **Transport Layer: Brief Explanation**

The **Transport Layer** is the **4th layer** in the **OSI model** and the **3rd layer** in the **TCP/IP model**. It ensures reliable, end-to-end communication between applications running on different hosts.  

#### **Key Functions of the Transport Layer:**
1. **Segmentation & Reassembly** – Breaks data into smaller units (segments/datagrams) for transmission and reassembles them at the destination.
2. **End-to-End Communication** – Establishes logical connections between sender and receiver.
3. **Flow Control** – Manages data flow to prevent overwhelming the receiver.
4. **Error Control & Reliability** – Detects and retransmits lost/corrupted data (in connection-oriented protocols).
5. **Multiplexing & Demultiplexing** – Allows multiple applications to use network services simultaneously via port numbers.

---

### **Types of Transport Layer Protocols**
1. **TCP (Transmission Control Protocol)**  
   - Connection-oriented (establishes a connection before sending data).  
   - Reliable (ensures delivery with acknowledgments).  
   - Provides flow control, error recovery, and ordered data transfer.  
   - Used for HTTP, FTP, SMTP, etc.

2. **UDP (User Datagram Protocol)**  
   - Connectionless (no handshake before sending data).  
   - Unreliable but faster (no retransmission of lost packets).  
   - No flow or congestion control.  
   - Used for DNS, VoIP, video streaming, online gaming.

3. Other Protocols:
   - SCTP (Stream Control Transmission Protocol) – Combines features of TCP & UDP.
   - DCCP (Datagram Congestion Control Protocol) – For time-sensitive applications.

---

### **How It Works?**
- Uses port numbers to identify applications (**e.g., HTTP = Port 80, HTTPS = 443**).
- TCP uses a three-way handshake (**SYN → SYN-ACK → ACK**) to establish a connection.
- UDP sends data directly without any setup.
- Ensures proper delivery by managing acknowledgments (TCP) or simply transmitting without guarantees (UDP).

---

### Summary:

| **Feature**               | **TCP (Transmission Control Protocol)**                          | **UDP (User Datagram Protocol)**                          |
|---------------------------|-----------------------------------------------------------------|----------------------------------------------------------|
| **Connection Type**       | Connection-oriented (3-way handshake)                           | Connectionless (no handshake)                            |
| **Reliability**           | Reliable (acknowledgments, retransmissions)                     | Unreliable (no retransmissions)                          |
| **Flow Control**          | Yes (sliding window mechanism)                                  | No                                                       |
| **Error Control**         | Yes (checksums, ACKs, retransmissions)                          | Minimal (only checksums for corruption detection)        |
| **Ordered Delivery**      | Yes (sequencing of segments)                                    | No (packets may arrive out of order)                     |
| **Speed**                 | Slower (overhead for reliability features)                      | Faster (low overhead)                                    |
| **Use Cases**             | HTTP, FTP, SMTP, SSH                                            | DNS, VoIP, Video Streaming, Online Gaming                |
| **Congestion Control**    | Yes (adjusts transmission rate dynamically)                     | No                                                       |
| **Header Size**           | Larger header (20+ bytes; options increase size)                | Smaller header (8 bytes fixed)                           |

### Additional Notes:
- **SCTP**: Combines reliability of TCP with speed of UDP; used in VoIP and multimedia.
- **DCCP**: Provides congestion control for unreliable traffic (e.g., streaming).

This table summarizes the key differences between TCP and UDP while aligning with the details from your notes. Let me know if you'd like any modifications!