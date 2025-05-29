

It looks like you're referring to **Out-of-Band SQL Injection (OOB SQLi)**, which is a type of SQL injection attack where the attacker retrieves data from a database by leveraging external network channels (like DNS, HTTP requests, or other protocols) rather than directly through the application's response.

### **Key Concepts of Out-of-Band SQLi:**
1. **How it Works**:
   - The attacker injects malicious SQL queries that force the database to make an outbound request (e.g., DNS lookup, HTTP call) containing stolen data.
   - The attacker monitors an external server they control to capture the exfiltrated data.

1. **When Used**:
   - When traditional **In-Band (Error-Based/Union-Based)** or **Blind SQLi** techniques don't work.
   - When the database has functions that allow external network