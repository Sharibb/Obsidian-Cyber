#!/bin/bash
# WSL2-Diag-Linux.sh
# Run inside WSL2: bash WSL2-Diag-Linux.sh

echo ""
echo "========== INTERFACES =========="
ip addr show

echo ""
echo "========== ROUTING TABLE =========="
ip route show

echo ""
echo "========== DEFAULT GATEWAY PING =========="
GW=$(ip route | grep default | awk '{print $3}')
echo "Gateway: $GW"
ping -c 3 -W 2 "$GW" 2>&1

echo ""
echo "========== INTERNET PING (1.1.1.1) =========="
ping -c 3 -W 2 1.1.1.1 2>&1

echo ""
echo "========== DNS RESOLUTION =========="
cat /etc/resolv.conf
echo ""
nslookup google.com 2>&1 || host google.com 2>&1

echo ""
echo "========== CURL TEST =========="
curl -v --max-time 5 http://1.1.1.1 2>&1 | head -30

echo ""
echo "========== ARP TABLE =========="
arp -n 2>/dev/null || ip neigh show

echo ""
echo "========== WSL CONF =========="
cat /etc/wsl.conf 2>/dev/null || echo "/etc/wsl.conf does not exist"

echo ""
echo "========== RESOLV CONF IMMUTABLE CHECK =========="
lsattr /etc/resolv.conf 2>/dev/null

echo ""
echo "========== IPTABLES RULES =========="
sudo iptables -L -n -v 2>/dev/null || echo "iptables not available or no rules"

echo ""
echo "========== KERNEL IP FORWARDING =========="
cat /proc/sys/net/ipv4/ip_forward

echo ""
echo "========== OS INFO =========="
cat /etc/os-release | grep -E "^NAME|^VERSION"
uname -r

echo ""
echo "========== DONE =========="
