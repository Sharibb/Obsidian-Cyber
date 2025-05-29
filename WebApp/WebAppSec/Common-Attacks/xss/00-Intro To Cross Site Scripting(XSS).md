

# Introduction to Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) is a common web security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. These attacks occur when an application includes untrusted data without proper validation or escaping.

## Key Concepts

1. **How XSS Works**:
   - Attacker injects malicious JavaScript code into a vulnerable website
   - Victim's browser executes the code in the context of the trusted site
   - Attacker can steal cookies, session tokens, or perform actions on behalf of the user

2. **Types of XSS**:
   - **Stored/Persistent XSS**: Malicious script is permanently stored on the target server
   - **Reflected XSS**: Malicious script is reflected off a web server in response
   - **DOM-based XSS**: Vulnerability exists in client-side code rather than server-side code

3. **Common Attack Vectors**:
   ```html
   <script>alert('XSS')</script>
   ```
   ```html
   <img src="x" onerror="alert('XSS')">
   ```
   ```javascript
   javascript:alert('XSS')
   ```

## Prevention Techniques

- Input validation and output encoding
- Implementing Content Security Policy (CSP)
- Using secure frameworks that auto-escape content
- Setting HttpOnly flag on cookies

Understanding XSS is fundamental for both developers (to prevent vulnerabilities) and security professionals (to test for them).

Further Explain the types of XSS extensively

 # **Introduction to Cross-Site Scripting (XSS) - Types Explained Extensively**

Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. These scripts execute in the victim's browser, potentially stealing sensitive data, hijacking sessions, or defacing websites.

XSS attacks are categorized into three main types:

1. **Reflected XSS**  
2. **Stored XSS**  
3. **DOM-based XSS**  

Each type has distinct characteristics and exploitation methods.

---

## **1. Reflected XSS (Non-Persistent)**
Reflected XSS occurs when malicious input from a user is immediately returned by the web application in an unsafe manner, typically in an error message, search result, or URL parameter.

### **How It Works:**
- The attacker crafts a malicious URL containing JavaScript.
- The victim clicks the link (e.g., via phishing).
- The server reflects the script back in the response.
- The victim's browser executes the script.

### **Example:**
```http
https://example.com/search?query=<script>alert('