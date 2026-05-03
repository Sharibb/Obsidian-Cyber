#Requires -RunAsAdministrator
<#
.SYNOPSIS
    WSL2 Port Proxy Manager for HTB / Reverse Shell workflows.

.DESCRIPTION
    Manages netsh portproxy rules between Windows (VPN) and WSL2.
    Supports single ports, port ranges, bulk add/remove, and dynamic WSL2 IP detection.

.EXAMPLES
    .\WSL2-PortProxy.ps1 -Action add -Ports 4444
    .\WSL2-PortProxy.ps1 -Action add -Ports 4444-4450
    .\WSL2-PortProxy.ps1 -Action add -Ports 4444,5555,8080
    .\WSL2-PortProxy.ps1 -Action add -Ports 4444 -ListenAddress 10.10.14.7
    .\WSL2-PortProxy.ps1 -Action add -Ports 4444 -WSL2IP 172.24.16.1
    .\WSL2-PortProxy.ps1 -Action remove -Ports 4444,4445
    .\WSL2-PortProxy.ps1 -Action remove -Ports 4444-4450
    .\WSL2-PortProxy.ps1 -Action list
    .\WSL2-PortProxy.ps1 -Action flush
    .\WSL2-PortProxy.ps1 -Action reset
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("add", "remove", "list", "flush", "reset")]
    [string]$Action,

    [string]$Ports,

    [string]$ListenAddress = "0.0.0.0",

    [string]$WSL2IP,

    [string]$DefaultPorts = "4444,4445,5555,8080,9001,9002,1234"
)

function Write-OK   { param($m) Write-Host "[+] $m" -ForegroundColor Green  }
function Write-INFO { param($m) Write-Host "[*] $m" -ForegroundColor Cyan   }
function Write-WARN { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-ERR  { param($m) Write-Host "[-] $m" -ForegroundColor Red    }
function Write-HEAD { param($m) Write-Host "`n=== $m ===" -ForegroundColor Magenta }

function Get-WSL2IP {
    param([string]$Override)

    if ($Override) {
        Write-INFO "Using manually specified WSL2 IP: $Override"
        return $Override
    }

    # Method 1: eth0
    try {
        $raw = wsl -- ip addr show eth0 2>$null
        if ($raw) {
            $match = [regex]::Match($raw, 'inet (\d+\.\d+\.\d+\.\d+)')
            if ($match.Success) {
                $ip = $match.Groups[1].Value
                Write-INFO "Auto-detected WSL2 IP (eth0): $ip"
                return $ip
            }
        }
    } catch {}

    # Method 2: eth1
    try {
        $raw = wsl -- ip addr show eth1 2>$null
        if ($raw) {
            $match = [regex]::Match($raw, 'inet (\d+\.\d+\.\d+\.\d+)')
            if ($match.Success) {
                $ip = $match.Groups[1].Value
                Write-INFO "Auto-detected WSL2 IP (eth1): $ip"
                return $ip
            }
        }
    } catch {}

    # Method 3: vEthernet (WSL) adapter on Windows side
    try {
        $addr = Get-NetIPAddress -InterfaceAlias "vEthernet (WSL)" -AddressFamily IPv4 -ErrorAction Stop
        if ($addr.IPAddress) {
            Write-WARN "Falling back to vEthernet (WSL) IP: $($addr.IPAddress)"
            return $addr.IPAddress
        }
    } catch {}

    Write-ERR "Could not auto-detect WSL2 IP. Use -WSL2IP to specify manually."
    exit 1
}

function Resolve-Ports {
    param([string]$Spec)

    if (-not $Spec) {
        Write-ERR "No ports specified. Examples: -Ports 4444   -Ports 4444-4450   -Ports 4444,5555"
        exit 1
    }

    $result = @()
    foreach ($token in ($Spec -split ',')) {
        $token = $token.Trim()
        if ($token -match '^(\d+)-(\d+)$') {
            $start = [int]$Matches[1]
            $end   = [int]$Matches[2]
            if ($start -gt $end) {
                $tmp = $start
                $start = $end
                $end = $tmp
            }
            if (($end - $start) -gt 500) {
                Write-WARN "Range $start-$end is large ($(($end - $start + 1)) ports). Continuing..."
            }
            $result += $start..$end
        } elseif ($token -match '^\d+$') {
            $result += [int]$token
        } else {
            Write-WARN "Skipping unrecognised token: '$token'"
        }
    }

    $invalid = $result | Where-Object { $_ -lt 1 -or $_ -gt 65535 }
    if ($invalid) {
        Write-ERR "Invalid port numbers: $($invalid -join ', ')"
        exit 1
    }

    return ($result | Sort-Object -Unique)
}

function Add-ProxyRules {
    param(
        [int[]]$PortList,
        [string]$ListenAddr,
        [string]$TargetIP
    )

    Write-HEAD "Adding $($PortList.Count) rule(s) -> WSL2 $TargetIP"
    $ok   = 0
    $skip = 0
    $fail = 0

    foreach ($port in $PortList) {
        $existing = netsh interface portproxy show v4tov4 | Select-String "$port"
        if ($existing) {
            Write-WARN "Rule already exists for port $port -- skipping (remove first to update)"
            $skip++
            continue
        }

        $null = netsh interface portproxy add v4tov4 `
            listenaddress=$ListenAddr `
            listenport=$port `
            connectaddress=$TargetIP `
            connectport=$port 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-OK "${ListenAddr}:${port} -> ${TargetIP}:${port}"
            $ok++
        } else {
            Write-ERR "Failed on port $port"
            $fail++
        }
    }

    Write-Host ""
    Write-INFO "Added: $ok  |  Skipped: $skip  |  Failed: $fail"
}

function Remove-ProxyRules {
    param(
        [int[]]$PortList,
        [string]$ListenAddr
    )

    Write-HEAD "Removing $($PortList.Count) rule(s)"
    $ok   = 0
    $miss = 0

    foreach ($port in $PortList) {
        $null = netsh interface portproxy delete v4tov4 `
            listenaddress=$ListenAddr `
            listenport=$port 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-OK "Removed ${ListenAddr}:${port}"
            $ok++
        } else {
            Write-WARN "No rule found for ${ListenAddr}:${port}"
            $miss++
        }
    }

    Write-Host ""
    Write-INFO "Removed: $ok  |  Not found: $miss"
}

function Show-ProxyRules {
    Write-HEAD "Current portproxy rules"
    $raw = netsh interface portproxy show v4tov4
    if (-not $raw -or $raw -match 'no') {
        Write-WARN "No portproxy rules configured."
    } else {
        Write-Host $raw
    }
}

function Flush-ProxyRules {
    Write-HEAD "Flushing ALL portproxy rules"
    netsh interface portproxy reset | Out-Null
    Write-OK "All portproxy rules removed."
}

function Ensure-FirewallRules {
    $ruleName = "WSL2-PortProxy-HTB"
    $exists = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $exists) {
        Write-INFO "Adding firewall allow rule for HTB ranges..."
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction Inbound `
            -Action Allow `
            -Protocol TCP `
            -RemoteAddress "10.0.0.0/8" | Out-Null
        Write-OK "Firewall rule '$ruleName' created."
    }
}

# MAIN

Write-Host ""
Write-Host "  WSL2 Port Proxy Manager" -ForegroundColor White
Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
Write-Host ""

switch ($Action) {

    "add" {
        Ensure-FirewallRules
        $wslIP = Get-WSL2IP -Override $WSL2IP
        $ports = Resolve-Ports -Spec $Ports
        Add-ProxyRules -PortList $ports -ListenAddr $ListenAddress -TargetIP $wslIP
    }

    "remove" {
        $ports = Resolve-Ports -Spec $Ports
        Remove-ProxyRules -PortList $ports -ListenAddr $ListenAddress
    }

    "list" {
        Show-ProxyRules
    }

    "flush" {
        $confirm = Read-Host "Flush ALL portproxy rules? (y/N)"
        if ($confirm -match '^[Yy]') {
            Flush-ProxyRules
        } else {
            Write-WARN "Aborted."
        }
    }

    "reset" {
        $confirm = Read-Host "Flush all rules and reload defaults ($DefaultPorts)? (y/N)"
        if ($confirm -match '^[Yy]') {
            Ensure-FirewallRules
            $wslIP = Get-WSL2IP -Override $WSL2IP
            Flush-ProxyRules
            $ports = Resolve-Ports -Spec $DefaultPorts
            Add-ProxyRules -PortList $ports -ListenAddr $ListenAddress -TargetIP $wslIP
            Write-INFO "Default ports loaded: $DefaultPorts"
        } else {
            Write-WARN "Aborted."
        }
    }
}

Write-Host ""
