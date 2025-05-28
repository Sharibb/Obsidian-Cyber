

**Title: Cryptographic Failure**  

**Description:**  
Cryptographic failures occur when sensitive data is improperly protected due to weak or misconfigured encryption, hashing, or key management. This can lead to exposure of confidential information such as passwords, credit card numbers, or session tokens.  

### **Common Causes:**  
1. **Weak Encryption Algorithms** (e.g., using outdated ciphers like DES or MD5).  
2. **Insecure Key Management** (e.g., hardcoded keys, insufficient key rotation).  
3. **Improper Hashing** (e.g., storing passwords without salting or using fast hash functions like SHA-1).  
4. **Lack of Transport Layer Security (TLS)** (e.g., transmitting data over unencrypted HTTP).  

### **Impact:**  
- Unauthorized access to sensitive data.  
- Session hijacking or impersonation attacks.  
- Compliance violations (e.g., GDPR, PCI-DSS).  

### **Mitigation Strategies:**  
✅ Use strong, up-to-date algorithms (AES-256 for encryption, bcrypt/Argon2 for hashing).  
✅ Enforce TLS (HTTPS) for all data in transit.  
✅ Store keys securely (HSMs, environment variables) and rotate them regularly.  
✅ Apply proper salting and stretching techniques for password storage.  

🔍 **OWASP Reference:** [A02:2023 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)  

Would you like a deeper dive into any specific aspect?