

# **Reflected XSS (In-Depth)**

## **Overview**
Reflected Cross-Site Scripting (XSS) is a type of web vulnerability where an attacker injects malicious scripts into a web application, which are then reflected back to the victim's browser. Unlike stored XSS, reflected XSS does not persist on the server—it is executed only when a user interacts with a specially crafted URL or input.

---

## **How Reflected XSS Works**
1. **Injection Point**: The attacker identifies a vulnerable parameter in a web application (e.g., search box, URL parameters).
2. **Malicious Payload**: The attacker crafts a URL containing malicious JavaScript.
3. **Victim Interaction**: The victim clicks the malicious link (e.g., via phishing).
4. **Execution**: The server reflects the payload back in the response, executing it in the victim’s browser.

### **Example Scenario**
- Vulnerable URL:  
  `https://example.com/search?query=<script>alert('XSS')</script>`
- When visited, the script executes in the user's browser.

---

## **Common Injection Vectors**
1. **URL Parameters**  
   - `?search=<script>alert(1)</script>`
2. **Form Inputs**  
   - `<input type="text" value="<img src=x onerror=alert(1)>">`
3. **HTTP Headers**  
   - `User-Agent: <script>alert(1)</script>`

---

## **Payload Examples**
### Basic Alert:
```html
<script>alert('XSS')</script>
```
### Image Tag with `onerror`:
```html
<img src=x onerror=alert(1)>
```
### SVG-Based XSS:
```html
<svg onload=alert(1)>
```
### JavaScript Events:
```html
<a href="#" onclick="alert('XSS')">Click Me</a>
```

---

## **Impact of Reflected XSS**
- Stealing cookies (`document.cookie`)
- Session hijacking
- Phishing attacks (fake login forms)
- Keylogging
- Defacement

---

## **Prevention & Mitigation**
1. **Input Validation**  
   - Whitelist allowed characters.
   - Reject or sanitize suspicious inputs.
2. **Output Encoding**  
   - Use HTML entity encoding (`&lt;

Append AFter Prevention & Mitigation

 Here’s the continuation of the **Prevention & Mitigation** section, followed by additional relevant content to complete the guide:

---

## **Prevention & Mitigation (