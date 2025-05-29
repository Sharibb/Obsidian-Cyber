
# NMAP Host Discovery Cheat Sheet

NMAP (Network Mapper) is a powerful tool for network discovery and security auditing. Host discovery is the first step in network scanning, where NMAP determines which hosts are online before performing more intensive scans.

## Host Discovery Techniques

| Command | Description | Example |
|---------|-------------|---------|
| `-sn` | Ping scan (no port scan) - sends ICMP echo, TCP SYN to 443, TCP ACK to 80, and ICMP timestamp requests | `nmap -sn 192.168.1.0/24` |
| `-Pn` | Treat all hosts as online (skip host discovery) | `nmap -Pn 192.168.1.100` |
| `-PS` | TCP SYN ping (specify ports) | `nmap -PS22,80,443 192.168.1.100` |
| `-PA` | TCP ACK ping (specify ports) | `nmap -PA22,80,443 192.168.1.100` |
| `-PU` | UDP ping (specify ports) | `nmap -PU53,161 192.168.1.100` |
| `-PY` | SCTP INIT ping (specify ports) | `nmap -PY80,5060 192.168.1.100` |
| `-PE` | ICMP echo request ping (standard ping) | `nmap -PE 192.168.1.100` |
| `-PP` | ICMP timestamp request ping | `nmap -PP 192.168.1.100` |
| `-PM` | ICMP netmask request ping (rarely used) | `nmap -PM 192.168.1.100` |
| `-PO[protocol list]` | IP protocol ping (specify protocol numbers) | `nmap -PO2,6,17 192.168..1..100` |

## Advanced Options

| Command          | Description                                    |
| ---------------- | ---------------------------------------------- |
| `--traceroute`   | Perform traceroute to each host                |
| `--packet-trace` | Show all packets sent and received             |
| `--reason`       | Display reason for port/host state conclusions |
|                  |                                                |
