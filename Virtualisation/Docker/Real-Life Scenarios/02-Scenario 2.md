# Seamless Docker + VPN Networking for Pentesting Containers

This guide explains how to make a **Docker Kali container work
seamlessly with a VPN (e.g., HackTheBox / lab VPN)** while keeping
**bridge networking** and avoiding `--network host`.

This setup ensures tools like:

-   nmap -sS
-   rustscan
-   masscan
-   metasploit
-   scapy

work normally through the VPN.

------------------------------------------------------------------------

# Problem

When running Kali in Docker with a custom bridge network:

docker run -it\
--network pentesting\
--cap-add NET_ADMIN\
--cap-add NET_RAW\
--name kali\
-v /media/dork/Backup/pentesting:/mnt/pentest\
kali-backup

Scanning targets on the VPN (example):

10.129.x.x

Tools like nmap or rustscan may:

-   hang during SYN scans
-   show no open ports
-   behave inconsistently

Example:

rustscan -a 10.129.17.66

Output:

Looks like I didn't find any open ports

------------------------------------------------------------------------

# Root Cause

Docker bridge networks do **not inherit host routing rules**.

Host routing table:

10.129.0.0/16 dev tun0

But inside the container:

default via 172.30.0.1 172.30.0.0/16 dev eth0

The container **does not know that the VPN network should go through
tun0**.

Traffic incorrectly goes:

container → docker bridge → default gateway

instead of:

container → docker bridge → host → tun0 → VPN

------------------------------------------------------------------------

# Solution

Add a route inside the container directing the VPN subnet to the Docker
gateway.

Example:

ip route add 10.129.0.0/16 via 172.30.0.1

This tells the container:

VPN network → send packets to Docker gateway

The host then forwards traffic through the VPN interface.

------------------------------------------------------------------------

# Full Working Setup

## 1. Remove old Docker network

docker network rm pentesting

------------------------------------------------------------------------

## 2. Create a dedicated pentesting network

docker network create\
--driver bridge\
--subnet 172.30.0.0/16\
--opt com.docker.network.driver.mtu=1500\
pentesting

------------------------------------------------------------------------

## 3. Run Kali container

docker run -it\
--network pentesting\
--cap-add NET_ADMIN\
--cap-add NET_RAW\
--name kali\
-v /media/dork/Backup/pentesting:/mnt/pentest\
kali-backup

------------------------------------------------------------------------

## 4. Add route to VPN network

Inside the container:

ip route add 10.129.0.0/16 via 172.30.0.1

------------------------------------------------------------------------

# Verification

Check routes:

ip route

Expected:

default via 172.30.0.1 dev eth0 172.30.0.0/16 dev eth0 10.129.0.0/16 via
172.30.0.1

Test connectivity:

ping 10.129.17.66

Run scan:

nmap -sS -Pn -T4 10.129.17.66

or

rustscan -a 10.129.17.66

------------------------------------------------------------------------

# Make It Automatic

Start the container with the route added automatically:

docker run -it\
--network pentesting\
--cap-add NET_ADMIN\
--cap-add NET_RAW\
--name kali\
-v /media/dork/Backup/pentesting:/mnt/pentest\
kali-backup\
bash -c "ip route add 10.129.0.0/16 via 172.30.0.1 && exec bash"

------------------------------------------------------------------------

# Network Flow After Fix

Kali Container (172.30.x.x) ↓ Docker Bridge ↓ Docker Gateway
(172.30.0.1) ↓ Host Routing ↓ tun0 (VPN) ↓ HTB / Lab Network
(10.129.x.x)

------------------------------------------------------------------------

# Advantages of This Setup

✔ Works with VPNs (tun0, wg0)\
✔ Keeps Docker isolation (no host networking)\
✔ Full support for raw packet tools\
✔ Compatible with pentesting tools\
✔ Works with HTB / Pro Labs / internal labs

------------------------------------------------------------------------

# Tools Confirmed Working

-   nmap
-   rustscan
-   masscan
-   metasploit
-   bloodhound-python
-   scapy

------------------------------------------------------------------------

# Summary

The issue occurs because **Docker containers don't inherit host VPN
routes**.

Adding the VPN route qwer1234manually allows traffic to flow:

container → docker bridge → host → VPN

This results in **seamless pentesting networking while keeping Docker
isolation**.
