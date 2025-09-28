![[1.png]]

Add the `expressway.htb` to /etc/hosts
```bash
echo "10.10.11.87 >> /etc/hosts"
```
## Network Scan

### Rustscan

```bash
rustscan -a 10.10.11.87
```
