# WSL2 + HTB VPN Setup — Complete Troubleshooting Guide

> Documenting the full journey of getting reverse shells, port forwarding, and internet working
> with WSL2 (Kali) + OpenVPN on Windows for HackTheBox.

---

## Environment

| Component | Details |
|---|---|
| OS | Windows 11 (10.0.26200) |
| WSL2 Distro | Kali Linux 2026.1 |
| WSL Version | 2.6.3 |
| VPN Client | OpenVPN (TAP-Windows6 adapter) |
| Internet | WiFi (`192.168.0.108`) |
| HTB VPN IP | `10.10.14.7` |

---

## Problem 1: Reverse Shell Not Connecting

### Symptom
Could ping/scan HTB machines from Windows but reverse shells never connected back.

### Root Cause
WSL2 uses NAT by default — it has an internal IP (`172.x.x.x`) not reachable from the HTB network. The HTB machine called back to the WSL2 internal IP which is unreachable externally.

### Solution: Port Proxy (Windows → WSL2)

```powershell
netsh interface portproxy add v4tov4 `
  listenport=4444 `
  listenaddress=0.0.0.0 `
  connectaddress=<WSL2_IP> `
  connectport=4444
```

Set `LHOST` to the Windows VPN IP (`10.10.14.7`), not `0.0.0.0`.
The chain is: `HTB Machine → Windows tun0 IP:4444 → portproxy → WSL2:4444 → listener`

**Script built:** `WSL2-PortProxy.ps1` — manages portproxy rules with single ports, ranges, auto WSL2 IP detection.

---

## Problem 2: Tried Mirrored Networking — Broke Everything

### What Was Tried
Switched WSL2 to mirrored network mode (`networkingMode=mirrored` in `.wslconfig`) hoping WSL2 would share the Windows VPN interface directly.

### What Happened
- WSL2 got `eth2` with `10.10.14.7` instead of `tun0`
- Routes to HTB ranges appeared automatically via `eth2`
- BUT: packets to HTB targets got 100% loss despite correct routing
- Root cause: Windows did not forward packets from WSL2 back through the VPN adapter — reply packets stayed on the Windows side

### Attempted Fixes (all failed)
- `netsh interface ipv4 set interface forwarding=enabled` — no effect
- `New-NetFirewallRule` for HTB ranges — no effect  
- `Set-NetIPInterface -Forwarding Enabled` — no effect
- `Set-ItemProperty IPEnableRouter = 1` — **this broke internet later**
- `Restart-Service RemoteAccess` — service disabled on consumer Windows, irrelevant

### Conclusion
Mirrored mode does not cleanly share VPN adapters for this use case. **Reverted to NAT mode.**

---

## Problem 3: Internet Broken in WSL2 After Revert

### Symptom
After reverting to NAT mode and undoing all changes, WSL2 had no internet. Gateway ping (`172.28.128.1`) also failed.

### Diagnostics Run
Two scripts (`WSL2-Diag-Windows.ps1` and `WSL2-Diag-Linux.sh`) collected:
- Network adapters, IPs, routing tables
- NAT entries, HNS networks, WinNAT state
- Firewall rules, forwarding state, iptables

### Root Causes Found (in order of discovery)

#### Cause 1: IPEnableRouter registry key
Set to `1` during mirrored mode debugging — changed how Windows handles NAT routing internally. Fixed with:
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 0
```

#### Cause 2: Windows Firewall blocking ICMP from WSL2 subnet
Even after NAT was restored, gateway ping failed. Fixed with:
```powershell
New-NetFirewallRule -DisplayName "WSL2 ICMP Allow" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -RemoteAddress "172.28.128.0/20" -Action Allow
New-NetFirewallRule -DisplayName "WSL2 Subnet Allow" -Direction Inbound -RemoteAddress "172.28.128.0/20" -Action Allow
```

#### Cause 3: Rogue NAT entry from Docker Desktop
`Get-NetNat` revealed a `WSL-NAT` entry covering `192.168.0.0/24` — the WiFi subnet. This conflicted with WinNAT trying to NAT WSL2 traffic out through WiFi. Almost certainly left behind by Docker Desktop.

#### Cause 4: WinNAT not auto-creating WSL NAT after disruption
After all the service restarts, HNS/WinNAT lost its internal NAT binding for the WSL subnet.

### Final Fix That Worked

```powershell
# 1. Remove all manual NAT entries (including Docker's rogue one)
Remove-NetNat -Confirm:$false

# 2. Undo WeakHost changes
Set-NetIPInterface -InterfaceAlias "vEthernet (WSL)" -WeakHostSend Disabled -WeakHostReceive Disabled
Set-NetIPInterface -InterfaceAlias "WiFi" -WeakHostSend Disabled -WeakHostReceive Disabled

# 3. Shut down WSL and destroy the broken HNS network
wsl --shutdown
Get-HNSNetwork | Where-Object { $_.Name -eq "WSL" } | Remove-HNSNetwork

# 4. Restart HNS and WinNAT in correct order
Stop-Service winnat
Stop-Service hns
Start-Service hns
Start-Service winnat

# 5. Start WSL — HNS recreates everything cleanly
wsl -d kali-linux
```

**Why this works:** HNS manages WSL2 NAT internally via ICS. It does not need or want a manual `New-NetNat` entry. Destroying the HNS WSL network and restarting both services forces a clean rebuild of the entire NAT binding.

---

## Working Setup Summary

```
Windows:   OpenVPN connected → tun0 IP = 10.10.14.7
WSL2:      NAT mode, eth0 = 172.28.142.186, gateway = 172.28.128.1
PortProxy: 0.0.0.0:PORT → 172.28.142.186:PORT  (managed via WSL2-PortProxy.ps1)

Reverse shell flow:
  HTB Target → 10.10.14.7:4444 → portproxy → WSL2:4444 → nc/msfconsole
```

### For every HTB session
```powershell
# 1. Connect OpenVPN on Windows
# 2. Add portproxy for your listener port
.\WSL2-PortProxy.ps1 -Action add -Ports 4444

# 3. In WSL2 msfconsole
set LHOST 10.10.14.7
set LPORT 4444
```

---

## Scripts Produced

| Script | Purpose |
|---|---|
| `WSL2-PortProxy.ps1` | Manage portproxy rules — add/remove/list/flush/reset, port ranges, auto WSL2 IP detection |
| `WSL2-Diag-Windows.ps1` | Collect Windows network diagnostics for troubleshooting |
| `WSL2-Diag-Linux.sh` | Collect WSL2 Linux network diagnostics for troubleshooting |

---

## Things That Break WSL2 Internet — Never Do These

| Action | Why It Breaks Things |
|---|---|
| `Set IPEnableRouter = 1` | Changes Windows NAT routing behavior, breaks WinNAT |
| `Set-NetFirewallProfile -Enabled False` | Disables firewall but also breaks WinNAT packet inspection |
| `New-NetNat` manually | Conflicts with HNS-managed ICS NAT — HNS manages WSL NAT internally |
| `Set-NetIPInterface -Forwarding Enabled` on WiFi | Can interfere with default gateway routing |
| Leaving Docker Desktop WSL running | Docker creates its own NAT entries that conflict with WSL2 |

---

## Quick Reference: WSL2-PortProxy.ps1

```powershell
# Single port
.\WSL2-PortProxy.ps1 -Action add -Ports 4444

# Range
.\WSL2-PortProxy.ps1 -Action add -Ports 4444-4460

# Multiple
.\WSL2-PortProxy.ps1 -Action add -Ports 4444,5555,9001

# Specific listen address (VPN IP only)
.\WSL2-PortProxy.ps1 -Action add -Ports 4444 -ListenAddress 10.10.14.7

# Override WSL2 IP
.\WSL2-PortProxy.ps1 -Action add -Ports 4444 -WSL2IP 172.28.142.186

# Remove
.\WSL2-PortProxy.ps1 -Action remove -Ports 4444

# List all rules
.\WSL2-PortProxy.ps1 -Action list

# Nuke everything
.\WSL2-PortProxy.ps1 -Action flush

# Reset to defaults (4444,4445,5555,8080,9001,9002,1234)
.\WSL2-PortProxy.ps1 -Action reset
```
