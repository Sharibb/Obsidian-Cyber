

# SQL Injection (SQLi) - Introduction

SQL Injection is a web security vulnerability that allows attackers to interfere with the queries that an application makes to its database. It's one of the most common and dangerous web vulnerabilities.

## Basic Concepts

1. **What is SQLi?**
   - A technique where attackers insert malicious SQL statements into input fields
   - Can read sensitive data, modify database content, or execute admin operations

2. **How it works**
   - Applications concatenate user input directly into SQL queries
   - Attackers craft inputs that change the query structure

## Common Attack Types

1. **Classic SQLi**
   ```sql
   SELECT * FROM users WHERE username = 'admin'--' AND password = ''
   ```
   (The `--` comments out the rest of the query)

2. **Union-based**
   ```sql
   SELECT title, body FROM articles WHERE id=1 UNION SELECT username, password FROM users--
   ```

3. **Boolean-based Blind**
   ```sql
   SELECT * FROM products WHERE id=1 AND 1=1-- (returns normal page)
   SELECT * FROM products WHERE id=1 AND 1=2-- (returns error/empty)
   ```

4. **Time-based Blind**
   ```sql
   SELECT * FROM users WHERE username='admin' AND IF(1=1,SLEEP(5),0)--'
   ```

## Prevention Methods

- Use prepared statements with parameterized queries
- Implement proper input validation
- Apply the principle of least privilege for database accounts
- Use web application firewalls (WAFs)

Would you like me to elaborate on any specific aspect of SQL injection?