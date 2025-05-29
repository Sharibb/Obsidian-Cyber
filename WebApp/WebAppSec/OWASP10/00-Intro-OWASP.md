
---

### **Introduction to OWASP Top 10**  
The **OWASP Top 10** is a globally recognised list of the most critical web application security risks, published by the *Open Web Application Security Project (OWASP)*. It serves as a guideline for developers, security teams, and organisations to prioritise mitigation efforts.

---

### **Key Highlights (Starred Blocks)**  
1. **🔥 Purpose**:  
   - Standardises awareness of common vulnerabilities.  
   - Helps organisations focus resources on the most severe risks.  

2. **📌 Updated Regularly**:  
   - Revised every 3–4 years (e.g., 2021, 2027) to reflect evolving threats.  

3. **🎯 Target Audience**:  
   - Developers, pentesters, CISOs, and compliance teams.  

---
![[OWASP1.png]]

---

### **2021 OWASP Top 10 Categories** *(Brief Overview)*  
1. **[[01-Broken Access Control || Broken Access Control]]**  
2. **[[02-Cryptographic Failure||Cryptographic Failures]]**  
3. **[[03-Injection|Injection]]** (e.g., SQLi)  
4. **[[04-Insecure Design|Insecure Design]]** *(New in 2021)*  
5. **[[05-Security Misconfiguration|Security Misconfiguration]]**  
6. **[[06-Vulnerable&Outdated Components|Vulnerable and Outdated Components]]**  
7. **[[07-Identification & Authentication Failures|Identification and Authentication Failures]]**  
8. **[[08-Software&Data Integrity Failures| Software and Data Integrity Failures]]** *(New)*  
9. **[[09-Security Logging & Monitoring Failures]]**  
10. **[[10-SSRF|Server Side Request Forgery(SSRF)]]** *(New)*  

---

### **Why It Matters?** 🌍  
- Addresses >90% of real-world application vulnerabilities.  
- Aligns with compliance standards (e.g., PCI-DSS, ISO 27001).  

Also add owasp api list and info 

Here’s your updated document with the **OWASP API Security Top 10** included, formatted consistently with the existing content:

---

### **Introduction to OWASP Top 10**  
The **OWASP Top 10** is a globally recognised list of the most critical web application security risks, published by the *Open Web Application Security Project (OWASP)*. It serves as a guideline for developers, security teams, and organisations to prioritise mitigation efforts.

---

### **Key Highlights (Starred Blocks)**  
1. **🔥 Purpose**:  
   - Standardises awareness of common vulnerabilities.  
   - Helps organisations focus resources on the most severe risks.  

2. **📌 Updated Regularly**:  
   - Revised every 3–4 years (e.g., 2021, 2027) to reflect evolving threats.  

3. **🎯 Target Audience**:  
   - Developers, pentesters, CISOs, and compliance teams.  

---
![[OWASP1.png]]

---

### **2021 OWASP Top 10 Categories** *(Brief Overview)*  
1. **[[01-Broken Access Control || Broken Access Control]]**  
2. **[[02-Cryptographic Failure||Cryptographic Failures]]**  
3. **[[03-Injection|Injection]]** (e.g., SQLi)  
4. **[[04-Insecure Design|Insecure Design]]** *(New in 2021)*  
5. **[[05-Security Misconfiguration|Security Misconfiguration]]**  
6. **[[06-Vulnerable&Outdated Components|Vulnerable and Outdated Components]]**  
7. **[[07-Identification & Authentication Failures|Identification and Authentication Failures]]**  
8. **[[08-Software&Data Integrity Failures| Software and Data Integrity Failures]]** *(New)*  
9. **[[09-Security Logging & Monitoring Failures]]**  
10. **[[10-SSRF|Server Side Request Forgery(SSRF)]]** *(New)*  

---

### **OWASP API Security Top 10 (2019)** *(For API-Specific Risks)*   
Focused on vulnerabilities unique to APIs (REST, GraphQL, SOAP):  

1. **[API1: Broken Object Level Authorization](https://owasp.org/API-Security/editions/2019/en/)** – Unauthorized access to objects via
   
   Continue

 Here’s the continuation of the **OWASP API Security Top 10 (2019)** section, formatted for clarity and consistency with your document:

---

### **OWASP API Security Top 10 (2019)** *(For API-Specific Risks)*  
Focused on vulnerabilities unique to APIs (REST, GraphQL, SOAP):  

1. **[API1: Broken Object Level Authorization](https://owasp.org/API-Security/editions/2019/en/)**  
   - Unauthorized access to objects via insecure endpoints (e.g., `/users/{id}` exposing other users' data).  

2. **[API2: Broken User Authentication](https://owasp.org/API-Security/editions/2019/en/)**  
   - Weak or misconfigured authentication mechanisms (e.g., JWT flaws, credential stuffing).  

3. **[API3: Excessive Data Exposure](https://owasp.org/API-Security/editions/2019/en/)**  
   - APIs returning more data than needed (e.g., full user objects when only names are required).  

4. **[API4: Lack of Resources & Rate Limiting](https://owasp.org/API-Security/editions/2019/en/)**  
   - Missing throttling leading to brute force attacks or denial-of-service (DoS).  

5. **[API5: Broken Function Level Authorization](https://owasp.org/API-Security/editions/2019/en/)**  
   - Privilege escalation due to improper role checks (e.g., regular users accessing admin endpoints).  

6. **[API6: Mass Assignment](https://owasp.org/API-Security/editions/2019/en/)**
   - Binding client-provided data to internal objects without whitelisting (e.g., `isAdmin=true` in JSON payloads).  

7. **[API7: Security Misconfiguration](https://owasp.org/API-Security/editions/2019/en/)**
   - Default settings, verbose error messages, or unsecured cloud storage.  

8. **[API8: Injection](https://owasp.org/API-Security/editions/2019/en/)**
   - SQLi, NoSQLi, or command injection via unfiltered API inputs.  

9. **[API9: Improper Assets Management](https://owasp.org/api-security/assets-management/)**
  continue

 Here’s the complete and polished **OWASP API Security Top 10 (2019)** section, following your document's structure and style:

---

### **OWASP API Security Top 10 (2019)** *(For API-Specific Risks)*  
Focused on vulnerabilities unique to APIs (REST, GraphQL, SOAP):  

1. **[API1: Broken Object Level Authorization](https://owasp.org/API-Security/editions/2019/en/)**  
   - Unauthorized access to objects via insecure endpoints (e.g., `/api/users/{id}`).  

1. **[API2: Broken User Authentication](https://owasp.org/API-Security/editions/2019/en/)**  
   - Weak credential management, token leaks, or flawed session handling.  

1. **[API3: Excessive Data Exposure](https://owasp.org/API-Security/editions/2019/en/)**  
   - APIs returning more data than needed (e.g., full user objects instead of filtered fields).  

1. **[API4: Lack of Resources & Rate Limiting](https://owasp.org/API-Security/editions/2019/en/)**  
   - No throttling leads to brute-force attacks or denial-of-service (DoS).  

1. **[API5: Broken Function Level Authorization](https://owasp.org/API-Security/editions/2019/en/)**  
   - Privilege escalation due to missing role checks (e.g., admin APIs accessible to regular users).  

6. **[API