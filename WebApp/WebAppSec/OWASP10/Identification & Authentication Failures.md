from owasp top 10 

### **Identification & Authentication Failures**  
*(OWASP Top 10 Category)*  

#### **Definition**  
Identification and authentication failures occur when systems incorrectly implement user identity verification, session management, or credential handling, allowing attackers to compromise passwords, keys, or tokens—or exploit flaws to assume other users’ identities.  

#### **Common Vulnerabilities**  
1. **Weak Credentials**  
   - Default, weak, or easily guessable passwords (e.g., `admin:admin`).  
   - Lack of password complexity requirements or brute-force protection.  

2. **Poor Session Management**  
   - Session tokens exposed in URLs or logs.  
   - Missing session expiration or rotation after login.  

3. **Insecure Authentication Flows**  
   - Missing multi-factor authentication (MFA) for sensitive actions.  
   - Authentication bypass (e.g., modifying parameters like `userid=admin`).  

1. **Credential Stuffing & Leaks**  
   - Use of breached passwords due to lack of screening.  
   - Storing passwords in plaintext or with weak hashing (e.g., MD5).  

1. **Misconfigured Identity Providers**  
