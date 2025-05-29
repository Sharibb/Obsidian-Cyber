Data Link Layer of OSI


The **Data Link Layer (Layer 2)** of the **OSI model** is responsible for **node-to-node communication**, ensuring error-free data transfer between directly connected devices over a physical medium. Here’s a concise breakdown:

### **Key Functions of Layer 2:**
1. **Framing**:  
   - Segments data into **frames** with headers/trailers for synchronization and error detection.

1. **Physical Addressing (MAC Addressing)**:  
   - Uses **MAC addresses** (e.g., `00:1A:2B:3C:4D:5E`) to uniquely identify devices on a local network.

3. **Error Control**:  
   - Detects/corrects errors via techniques like **CRC (Cyclic Redundancy Check)**.

4. **Flow Control**:  
   - Manages data transmission speed to prevent overwhelming the receiver (e.g., using **sliding window protocols**).

5. **Access Control**:  
   - Governs how devices share the medium (e.g., **CSMA/CD** for Ethernet, **CSMA/CA** for Wi-Fi).

---

### **Layer-2 Protocols & Technologies:**
- **Ethernet (IEEE 802.3)