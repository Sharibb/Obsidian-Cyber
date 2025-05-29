## Session Layer of OSI


The **Session Layer (Layer 5)** of the **OSI (Open Systems Interconnection) model** is responsible for managing communication sessions between applications. Here’s a concise breakdown of its key functions:

### **Key Responsibilities:**
1. **Session Establishment, Maintenance & Termination:**  
   - Sets up, coordinates, and ends dialogues between applications (e.g., login/logout sequences).  
   - Manages full-duplex (two-way) or half-duplex (one-way at a time) communication.

1. **Synchronization & Checkpoints:**  
   - Inserts checkpoints in data streams to recover from failures without retransmitting entire sessions.  
   - Example: Resuming a large file transfer after interruption.

3. **Dialog Control:**  
   - Determines which device transmits data at a given time (token management in protocols like Kerberos).

1. **Authentication & Authorization:**  
   - Verifies session participants before data exchange begins (e.g., secure login processes).

### **Examples of Session Layer Protocols:**
- **NetBIOS** (Windows network sessions).  
- **RPC** (Remote Procedure Call).  
- **PPTP** (Point-to-Point Tunneling