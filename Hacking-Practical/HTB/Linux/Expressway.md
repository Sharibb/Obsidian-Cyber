![[1.png]]

Add the `expressway.htb` to /etc/hosts
```bash
echo "10.10.11.87 expressway.htb" >> /etc/hosts
```
## Network Scan

### Rustscan

```bash
rustscan -a expressway.htb -- -sV
```
