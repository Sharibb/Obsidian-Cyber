
After doing everything if ligolo doesnt work do this

```powershell
PS D:\pentesting\CPTS\WSL> route print | findstr 172.16.119
PS D:\pentesting\CPTS\WSL> Get-NetAdapter | Select-Object Name, ifIndex

Name                         ifIndex
----                         -------
OpenVPN Data Channel Offload      24
OpenVPN TAP-Windows6              23
Bluetooth Network Connection      22
htb-internal                       3
Ethernet                          21
vEthernet (WSL)                   52
WiFi                              16


PS D:\pentesting\CPTS\WSL> route add 172.16.119.0 mask 255.255.255.0 0.0.0.0 if 3 metric 5
 OK!
PS D:\pentesting\CPTS\WSL> route print | findstr 172.16.119
     172.16.119.0    255.255.255.0         On-link   169.254.161.155     10
   172.16.119.255  255.255.255.255         On-link   169.254.161.155    261
```