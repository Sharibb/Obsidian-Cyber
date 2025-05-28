
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

4. **Credential Stuffing & Leaks**  
   - Use of breached passwords due to lack of screening.  
   - Storing passwords in plaintext or with weak hashing (e.g., MD5).  

5. **Misconfigured Identity Providers**  
   - Incorrect OAuth/OpenID configurations allowing token theft or privilege escalation.  

---

#### **Examples of Attacks**  
- **Brute Force**: Automated login attempts against weak passwords.  
- **Session Hijacking**: Stealing session cookies via MITM or XSS.  
- **Password Reset Abuse**: Bypassing questions like "mother’s maiden name."  

---

#### **Mitigation Strategies**  
✅ **Implement Strong Authentication**: Enforce MFA and password policies (e.g., 12+ chars, checks against breach databases).  
✅ **Secure Session Handling**: Use HTTP-only, secure cookies; invalidate sessions after inactivity/role changes.  
✅ **Rate Limiting**: Block excessive login attempts (e.g., 5 failed tries → lockout).  
✅ **Avoid DIY Crypto**: Use standard libraries for password hashing (Argon2, bcrypt, PBKDF2).  

---

#### **OWASP References**  
- [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)  

