

# **Reflected XSS (In-Depth)**

## **Overview**
Reflected Cross-Site Scripting (XSS) is a type of web vulnerability where an attacker injects malicious scripts into a web application, which are then reflected back to the victim's browser. Unlike stored XSS, reflected XSS does not persist on the server—it is executed only when a user interacts with a specially crafted URL or input.

---

## **How Reflected XSS Works**
1. **Injection Point**: The attacker identifies a vulnerable parameter in a web application (e.g., search box, URL parameters).
2. **Malicious Payload**: The attacker crafts a URL containing malicious JavaScript.
3. **Victim Interaction**: The victim clicks the malicious link (e.g., via phishing).
4. **Execution**: The server reflects the payload back in the response, executing it in the victim’s browser.

### **Example