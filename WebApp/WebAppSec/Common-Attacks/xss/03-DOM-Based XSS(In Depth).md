
## **Overview**
DOM-Based Cross-Site Scripting (XSS) is a type of security vulnerability where the attack payload is executed as a result of modifying the Document Object Model (DOM) in the victim's browser. Unlike traditional XSS, which involves server-side flaws, DOM-based XSS occurs entirely on the client side.

---

## **Key Concepts**
### **1. How DOM-Based XSS Works**
- The attacker manipulates client-side JavaScript to inject malicious scripts.
- The vulnerability arises when unsafe user input is written into the DOM without proper sanitization.
- Common sources:
  - `document.location` (URL fragments, query parameters)
  - `document.referrer`
  - `window.name`
  - Form inputs processed by JavaScript

### **2. Example Attack Scenario**
```javascript
// Vulnerable code
var userInput = document.location.hash.substring(1);
document.write(userInput); // Unsafe DOM manipulation
```
**Exploitation:**
An attacker crafts a malicious URL:
```
https://example.com/page#<script>alert('XSS')</script>
```
When visited, the script executes in the victim's browser.

---

## **Types of DOM-Based XSS**
1. **Reflected DOM-XSS**  
   - Malicious input comes from a URL parameter and is immediately reflected in the DOM.
   - Example:  
     ```javascript
     var searchTerm = new URLSearchParams(window.location.search).get('q');
     document.getElementById('search-results').innerHTML = searchTerm; // Unsafe
     ```

2. **Stored DOM-XSS**  
   - Malicious payload is stored (e.g., in localStorage) and later retrieved & executed.
   - Example:  
     ```javascript
     var storedData = localStorage.getItem('userData');
     document.body.innerHTML += storedData; // Unsafe
     ```

3. **Mutated DOM-XSS (Advanced)**  
   - Browser quirks or frameworks modify HTML in unexpected ways, leading to script execution.

---

## **Detection & Exploitation**
### **Manual Testing Steps**
1. Identify sinks (dangerous JavaScript functions that write to DOM):
   - `innerHTML`, `outerHTML`, `document.write()`, `eval()`
   - jQuery’s `html()`, `append()`, etc.
1. Trace input sources (`location.hash`, `location.search

