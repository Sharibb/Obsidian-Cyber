

# **Blind XSS (In-Depth)**

## **Introduction to Blind XSS**
Blind XSS is a type of Cross-Site Scripting (XSS) attack where the attacker's payload is stored and executed in a different context than where it was injected, often in an admin panel or backend system. Unlike traditional stored XSS, the attacker does not immediately see the result of the payload execution.

### **Key Characteristics:**
- **Delayed Execution**: The payload triggers at a later time when accessed by another user (e.g., an admin).
- **No Immediate Feedback**: The attacker does not see the response directly.
- **Harder to Detect**: Since the payload executes in a different context, traditional scanners may miss it.

---

## **How Blind XSS Works**
1. **Payload Injection**: Attacker submits malicious input (e.g., via contact forms, comments, or user profiles).
2. **Storage on Server**: The input is stored in a database or log file.
3. **Triggered Execution**: When an admin or another privileged user views the stored data, the payload executes.
4. **Exfiltration of Data**: The payload sends sensitive information (cookies, session tokens) back to the attacker.

---

## **Common Attack Vectors**
1. **Admin Dashboards**  
   - Admin panels often review user-submitted data (e.g., support tickets, logs).
2. **Log Files**  
   - Web servers store logs that may include malicious input.
1. **User Profiles**  
   - Some systems allow HTML/JS in profile fields that admins review.
4. **Feedback Forms**  
   - Attackers submit malicious scripts that execute when reviewed.

---

## **Exploiting Blind XSS**
### **(1) Crafting Payloads**
Since feedback is delayed, attackers use callback mechanisms:
```html
