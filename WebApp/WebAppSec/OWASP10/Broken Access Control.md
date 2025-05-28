![[owasp-top-10-broken-access-control.webp]]

### **Broken Access Control: Understanding and Mitigating the Risk**

#### **What is Broken Access Control?**
Broken Access Control occurs when an application fails to properly enforce restrictions on what authenticated users are allowed to do. Attackers can exploit these flaws to access unauthorized functionality or data, such as:

- **Horizontal Privilege Escalation**: Accessing another user's data with the same privilege level (e.g., viewing another user’s account details).
- **Vertical Privilege Escalation**: Gaining higher privileges (e.g., an ordinary user accessing admin functions).
- **Forced Browsing**: Directly accessing restricted URLs without proper authorization.

#### **Common Examples**
1. **Insecure Direct Object References (IDOR)**  
   - Example: `https://example.com/profile?id=123` where changing `id=124` allows access to another user’s profile.
   
2. **Missing Function-Level Access Control**  
   - Example: An admin panel URL (`/admin/dashboard`) is accessible to regular users because the server doesn’t validate roles.

3. **API Abuse via Missing Rate Limits**  
   - Example: An attacker brute-forces password reset tokens due to lack of rate limiting.

4. **CORS Misconfigurations**  
   - Example: A poorly configured API allows any domain (`Access-Control-Allow-Origin: *`) to access sensitive data.


---
![[BAC1.jpg]]

---
#### **Impact**
- Unauthorized data exposure (PII, financial records).
- Account takeovers.
- Compliance violations (GDPR, HIPAA).

---

### **How to Prevent Broken Access Control**
1. **Implement Role-Based Access Control (RBAC)**  
   - Enforce strict checks for every request (e.g., "Is this user an admin?").

2. **Validate Permissions Server-Side**  
   - Never rely on client-side checks alone; attackers can bypass them.

3. **Use Indirect Object References**  
   - Replace direct database IDs with UUIDs or mapped tokens (e.g., `/profile?token=abc123` instead of `/profile?id=1`).

4. **Deny by Default**  
   - Ensure all endpoints explicitly deny access unless authorized.

5. **Log and Monitor Access Attempts**  
   - Detect anomalies like repeated unauthorized requests.

6. **Automate Testing**  
   - Use tools like OWASP ZAP or Burp Suite to scan for access control flawshe **OWASP Top 10**, formatted with starred blocks for key concepts:


Here’s a refined and consolidated version of your content on **Broken Access Control**, with improved structure, clarity, and no duplication:

---

### **Broken Access Control: Risks & Mitigation**  
**OWASP Top 10 | Critical Security Risk**  

#### **Definition**  
Broken Access Control occurs when applications fail to enforce authorisation checks, allowing users to act beyond their intended permissions.  

---

### **Attack Types**  
1. **Horizontal Privilege Escalation**  
   - Accessing another user’s data at the same privilege level (e.g., `/profile?id=123` → `id=124`).  
2. **Vertical Privilege Escalation**  
   - Gaining elevated access (e.g., regular user accessing `/admin/dashboard`).  
3. **Forced Browsing**  
   - Directly requesting restricted URLs (e.g., `/internal/reports`).  

---

### **Common Exploits**  
1. **IDOR (Insecure Direct Object Reference)**  
   - Manipulating parameters like database IDs (`/invoice?id=1001`). Fix: Use UUIDs or tokens.  
2. **Missing Role Checks**  
   - Admin APIs without server-side validation. Fix: Enforce RBAC on every request.  
3. **Rate Limit Bypass**  
   - Brute-forcing endpoints (e.g., password resets). Fix: Implement throttling.  

---

### **Impact**  
- Data leaks (PII, financial records).  
- Account takeovers & regulatory fines (GDPR/HIPAA).  

---

### **Prevention Strategies** (**Key Fixes**)  

1. ***Role-Based Access Control (RBAC)***  
   - Enforce granular permissions (e.g., `user.can_edit_profile = false`).  

2. ***Server-Side Validation*** (**Never trust client-side checks!**)  
   - Reject requests unless explicitly authorized.  

3. ***Indirect References*** (**Avoid exposing DB IDs**)   
   - Use UUIDs (`/profile?token=a1b2c3`) instead of sequential IDs (`id=123`).  

4. ***Default-Deny Principle*** (**Zero Trust**)   
   - Block all access by default; whitelist permitted actions only.

5. ***Logging & Monitoring*** (**Detect anomalies**)   
   - Alert on repeated unauthorized access attempts.

---

![[BAC2.png]]