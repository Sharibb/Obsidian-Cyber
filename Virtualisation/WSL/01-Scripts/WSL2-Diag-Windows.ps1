# WSL2-Diag-Windows.ps1
# Run as Admin in PowerShell

Write-Host "`n========== NETWORK ADAPTERS ==========" -ForegroundColor Cyan
Get-NetAdapter | Select-Object Name, InterfaceDescription, ifIndex, Status, MacAddress, LinkSpeed | Format-Table -AutoSize

Write-Host "`n========== IP ADDRESSES ==========" -ForegroundColor Cyan
Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize

Write-Host "`n========== ROUTING TABLE ==========" -ForegroundColor Cyan
Get-NetRoute -AddressFamily IPv4 | Select-Object InterfaceAlias, DestinationPrefix, NextHop, RouteMetric | Sort-Object InterfaceAlias | Format-Table -AutoSize

Write-Host "`n========== PORTPROXY RULES ==========" -ForegroundColor Cyan
netsh interface portproxy show all

Write-Host "`n========== WINNAT STATE ==========" -ForegroundColor Cyan
Get-Service winnat | Select-Object Name, Status, StartType

Write-Host "`n========== HNS STATE ==========" -ForegroundColor Cyan
Get-Service hns | Select-Object Name, Status, StartType

Write-Host "`n========== HNS NETWORKS ==========" -ForegroundColor Cyan
try {
    Get-HNSNetwork | Select-Object Name, Type, Subnets | Format-List
} catch {
    Write-Host "HNSNetwork cmdlet not available: $_" -ForegroundColor Yellow
}

Write-Host "`n========== FIREWALL PROFILES ==========" -ForegroundColor Cyan
Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize

Write-Host "`n========== FIREWALL RULES (HTB/WSL related) ==========" -ForegroundColor Cyan
Get-NetFirewallRule | Where-Object {
    $_.DisplayName -like "*WSL*" -or
    $_.DisplayName -like "*HTB*" -or
    $_.DisplayName -like "*proxy*" -or
    $_.DisplayName -like "*forward*"
} | Select-Object DisplayName, Enabled, Direction, Action | Format-Table -AutoSize

Write-Host "`n========== IP FORWARDING (REGISTRY) ==========" -ForegroundColor Cyan
$fwd = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -ErrorAction SilentlyContinue
if ($fwd) { Write-Host "IPEnableRouter = $($fwd.IPEnableRouter)" } else { Write-Host "IPEnableRouter not set (default 0)" }

Write-Host "`n========== INTERFACE FORWARDING STATE ==========" -ForegroundColor Cyan
Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias, Forwarding, WeakHostSend, WeakHostReceive | Format-Table -AutoSize

Write-Host "`n========== PING GATEWAY TEST ==========" -ForegroundColor Cyan
$wslGW = (Get-NetIPAddress -InterfaceAlias "vEthernet (WSL)" -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
if ($wslGW) {
    Write-Host "vEthernet (WSL) IP: $wslGW"
    ping -n 3 $wslGW
} else {
    Write-Host "vEthernet (WSL) adapter not found!" -ForegroundColor Red
}

Write-Host "`n========== WSL VERSION ==========" -ForegroundColor Cyan
wsl --version 2>$null
wsl --list --verbose 2>$null

Write-Host "`n========== DONE ==========" -ForegroundColor Green
