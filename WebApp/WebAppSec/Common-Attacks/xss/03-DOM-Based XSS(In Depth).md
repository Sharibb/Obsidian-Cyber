

# **03-DOM-Based XSS (In Depth)**

## **Overview**
DOM-Based Cross-Site Scripting (XSS) is a type of security vulnerability where the attack payload is executed as a result of modifying the Document Object Model (DOM) in the victim's browser. Unlike traditional XSS, which involves server-side flaws, DOM-based XSS occurs entirely on the client side.

---

## **Key Concepts**
### **1. How DOM-Based XSS Works**
- The attacker manipulates client-side JavaScript to inject malicious scripts.
- The vulnerability arises when unsafe user input is written into the DOM without proper sanitization.
- Common sources:
  - `