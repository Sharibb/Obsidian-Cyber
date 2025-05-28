From owasp top 10

 The **Insecure Design** category in the **OWASP Top 10** refers to security risks that arise from flaws or missing controls in the design phase of software or systems, rather than implementation bugs or misconfigurations. Unlike vulnerabilities like SQL injection or XSS (which stem from coding errors), insecure design flaws are "baked in" due to inadequate threat modeling, poor architectural decisions, or failure to enforce security principles early in development.

### **Key Aspects of Insecure Design**:
1. **Missing Security Controls**:  
   - Lack of authentication/authorization checks for critical workflows.  
   - Absence of rate limiting, leading to brute-force attacks.  

1. **Flawed Business Logic**:  
   - Design allows abuse (e.g., purchasing negative quantities of items for profit).  
   - Weak password recovery mechanisms (e.g., answers to easily guessed questions).  

3. **Insecure Defaults**:  
   - Default admin credentials or overly permissive access roles.  

1. **Failure to Plan for Abuse Cases**:  
   - Assuming users will follow intended workflows without malicious intent (e.g., bypassing steps in a multi-step process).  

### **Examples**:
- A banking app designed without transaction verification for high-value transfers.  
- A hotel booking system that lets users reserve rooms without payment by manipulating API parameters.  

### **How to Mitigate**:
- **