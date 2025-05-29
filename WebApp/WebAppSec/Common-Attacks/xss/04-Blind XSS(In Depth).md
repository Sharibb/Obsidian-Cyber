

# **Blind XSS (In-Depth)**

## **Introduction to Blind XSS**
Blind XSS is a type of Cross-Site Scripting (XSS) attack where the attacker's payload is stored and executed in a different context than where it was injected, often in an admin panel or backend system. Unlike traditional stored XSS, the attacker does not immediately see the result of the payload execution.

### **Key Characteristics:**
- **Delayed Execution**: The payload triggers at a later time when accessed by another user (e.g., an admin).
- **No Immediate Feedback**: The attacker does not see the response