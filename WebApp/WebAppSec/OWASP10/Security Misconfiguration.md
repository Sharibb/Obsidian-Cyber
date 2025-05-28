from owasp top 10

 ### **Security Misconfiguration (OWASP Top 10)**  

#### **Overview**  
Security misconfiguration occurs when security settings are not properly defined, implemented, or maintained, leaving systems vulnerable to attacks. This can happen at any level of an application stack, including the network, server, database, application code, or cloud services.  

#### **Common Causes**  
1. **Default Credentials** – Leaving default usernames/passwords unchanged (e.g., `admin:admin`).  
2. **Unnecessary Features Enabled** – Running unused services (e.g., debug modes, sample apps).  
3. **Improper Error Handling** – Revealing sensitive information in error messages.  
4. **Outdated Software** – Using unpatched frameworks/libraries with known vulnerabilities.  
5. **Excessive Permissions** – Granting unnecessary privileges to users or services.  
6. **Misconfigured HTTP Headers** – Missing security headers like `Content-Security-Policy` or `X-XSS-Protection`.  

#### **Impact**  
- Unauthorized access to sensitive data (e.g., databases exposed due to weak authentication).  
- System compromise via default credentials or debug interfaces.  
- Data leakage through verbose error messages or directory listings.  

#### **Prevention & Mitigation**  
✅ **Secure Defaults:** Change default passwords and disable unnecessary features.  
✅ **Least Privilege Principle:** Restrict permissions for users and services to only what is necessary.  
✅ **Regular Updates:** Patch systems and dependencies promptly.  
✅ **