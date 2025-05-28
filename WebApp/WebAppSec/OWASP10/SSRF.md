
 ### **Server-Side Request Forgery (SSRF) - OWASP Top 10**

#### **What is SSRF?**
SSRF is a web security vulnerability where an attacker tricks a server into making unintended requests to internal or external resources. This can lead to:
- Access to sensitive internal systems (e.g., databases, admin panels).
- Data exfiltration (e.g., cloud metadata, internal APIs).
- Bypassing firewalls or authentication mechanisms.

---

### **How SSRF Works**
1. **Attacker Input**: A user-controlled input (e.g., URL, IP) is sent to the server.
2. **Server-Side Request**: The server fetches the resource without proper validation.
3. **Exploitation**: The attacker manipulates the request to access restricted resources.

**Example Vulnerable Code (PHP):**
```php
$url = $_GET['url']; // User-controlled input
$response = file_get_contents($url);
echo $response;
```
An attacker could abuse this by requesting:
```
http://victim.com/?url=http://localhost/admin
```

---

### **Common SSRF Attack Scenarios**
1. **Internal Network Access**  
   - Fetching `http://127.0.0.1:8080` (internal admin panel).  
   - Scanning ports (`http://internal-server:3306` for MySQL).  

2. **Cloud Metadata Exploitation**  
   - AWS: `http://169.254.169.254/latest/meta-data/`  
   - GCP: `http://metadata.google.internal/computeMetadata/v1/`  

3. **Protocol Abuse**  
   - Using `file://` to read local files (`file:///etc/passwd`).  
   - Using `dict://`, `gopher://`, or `sftp://` for further exploitation.

4. **Blind SSRF**  
   - No direct response, but the server makes outbound requests (e.g., webhook callbacks).

---

### **Preventing SSRF**
| **Mitigation**               | **Implementation** |
|------------------------------|--------------------|
| Input Whitelisting           | Allow only trusted domains/IPs (`api.example.com`). |
| Blocklist Dangerous Schemes  | Deny `file://`, `gopher://`, etc. |
| Use URL Parsers              | Validate hostnames and reject private IPs (`127.*