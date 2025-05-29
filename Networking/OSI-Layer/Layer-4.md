## Transport Layer of OSI


The **Transport Layer (Layer 4)** of the **OSI model** is responsible for end-to-end communication, error recovery, flow control, and ensuring complete data transfer between devices. Here’s a concise breakdown:

### **Key Functions of Layer 4**:
1. **Segmentation & Reassembly**:  
   - Breaks data into smaller units (*segments* in TCP, *datagrams* in UDP) for transmission and reassembles them at the destination.

1. **Connection Management**:  
   - **TCP (Transmission Control Protocol)**: Establishes reliable, connection-oriented sessions with acknowledgments (ACKs), retransmissions, and sequencing.  
   - **UDP (User Datagram Protocol)**: Provides connectionless, lightweight communication without guarantees (used for speed-sensitive applications like VoIP).

1. **Error Control & Flow Control**:  
   - Detects/corrects errors (e.g., via checks