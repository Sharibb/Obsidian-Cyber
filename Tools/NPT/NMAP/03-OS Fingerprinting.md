
### **Nmap OS Fingerprinting & Cheat Sheet**  

Nmap's **OS fingerprinting** is a technique used to identify the operating system (OS) of a target host by analyzing network responses, TCP/IP stack behavior, and other subtle differences in protocol implementations.  

#### **How Nmap OS Fingerprinting Works:**  
1. **TCP/IP Stack Analysis**: Nmap sends a series of probes (TCP, UDP, ICMP) and examines responses (e.g., TCP window size, TTL values).  
2. **Signature Matching**: The collected data is compared against a database (`nmap-os-db`) of known OS fingerprints.  
3. **Probability-Based Guess**: Nmap provides a confidence score (%) for its OS detection.  

#### **Basic Command for OS Detection:**  
```sh
nmap -O <target>  
```
- `-O`: Enables OS fingerprinting (requires root privileges).  
- `--osscan-limit`: Only scans hosts with open ports (faster).  
- `--osscan-guess` or `--fuzzy`: Makes educated guesses if an exact match isn't found.  

#### **Cheat Sheet for Common Scenarios:**  

| Command | Description |
|---------|-------------|
| `nmap -O 192.168.1.1` | Standard OS detection |
| `nmap -O --osscan-guess 192.168.1.1` | Aggressive guessing |
| `nmap -v -O --max-os-tries 1 192.168.1.1` | Faster scan (reduces retries) |
| `nmap -sV -O 192.168.1.0/24` | Combine with service version detection |

#### **Limitations & Considerations:**  
- Requires root/admin privileges (`sudo nmap` on Linux).  
- May be inaccurate if firewalls modify packets (e.g., NAT, IDS).  
- Some systems randomize TCP/IP stack behavior to evade detection (e.g., Linux with `sysctl` tweaks).  

For more details: [Nmap OS Detection Docs](https://nmap.org/book/man-os-detection.html)