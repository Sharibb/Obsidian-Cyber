owasp top 10

 **Security Logging & Monitoring Failures (A10:2021)** is a critical category in the **OWASP Top 10**, highlighting vulnerabilities that arise when systems fail to detect, log, or respond to security incidents effectively. Here’s a breakdown of its key aspects:

---

### **Why It Matters**
- **Attackers rely on gaps**: Poor logging/monitoring allows attackers to persist undetected, escalate privileges, or exfiltrate data.
- **Compliance risks**: Regulations (e.g., GDPR, PCI DSS) mandate logging for accountability and breach investigations.
- **Delayed response**: Without visibility, breaches may go unnoticed for months.

---

### **Common Failures**
1. **Insufficient Logging**  
   - Critical events (logins, access control changes) aren’t logged.
   - Logs lack context (timestamps, user IDs, source IPs).

1. **Poor Log Management**  
   - Logs aren’t stored securely or are overwritten too quickly.
   - No central aggregation (making correlation hard).

1. **No Real-Time Monitoring**  
   - Alerts aren’t triggered for suspicious activities (e.g., brute-force attacks).
   - Reliance on manual reviews instead of automated tools.

4. **Ignoring Logs**  
   - Logs are collected but never analyzed (e.g., missed SQL injection attempts in logs).

5. **Weak Incident Response**  
   - No playbook for investigating/alerts; slow reaction to breaches