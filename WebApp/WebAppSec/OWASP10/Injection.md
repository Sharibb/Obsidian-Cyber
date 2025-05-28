
![[Owasp Vulnerability SQL Injection.webp]]
## Overview
Injection flaws, ranked #3 in the OWASP Top 10 2021, occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing unauthorized data.

## Common Types of Injection Attacks
- **SQL Injection**: Manipulating database queries
- **NoSQL Injection**: Targeting NoSQL databases
- **OS Command Injection**: Executing system commands
- **LDAP Injection**: Manipulating LDAP queries
- **XPath Injection**: Targeting XML data stores

## Prevention Techniques

### Primary Defenses:
1. **Use Prepared Statements (Parameterized Queries)**
   - For SQL: `PreparedStatement` in Java, PDO in PHP
   - For NoSQL: Use official drivers with parameterized API

2. **Stored Procedures**
   - When properly implemented (without dynamic SQL)

3. **Input Validation**
   - Whitelist validation for known good values
   - Blacklist dangerous patterns as secondary measure

4. **Output Encoding**
   - Context-specific encoding before output

5. **Least Privilege**
   - Database accounts with minimal required permissions

### Additional Protections:
- Web Application Firewalls (WAF)
- Regular security testing and code reviews
- ORM frameworks with built-in protection

## Example Vulnerable Code (SQLi)
```php
$query = "SELECT * FROM users WHERE username = '" . $_POST['username'] . "'";
$result = mysql_query($query);
```

## Secure Alternative (Parameterized Query)
```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE username = :username');
$stmt->execute(['username' => $_POST['username']]);
```

Injection remains one of the most dangerous web application vulnerabilities due to its potential for complete system compromise. Always validate, sanitize, and parameterize all external inputs.