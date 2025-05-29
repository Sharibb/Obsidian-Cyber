

# Second-Order SQL Injection

Second-order SQL injection is a type of SQL injection attack where malicious input is initially stored in a database and later executed when that data is retrieved and used in an SQL query.

## Key Characteristics

1. **Delayed Execution**: The attack doesn't occur immediately when the input is first inserted into the database
2. **Storage-Based**: Malicious payloads persist in the database until triggered
3. **Context-Dependent**: The attack executes when the stored data is used in a vulnerable SQL query

## How It Works

1. Attacker submits malicious input that gets stored in the database
2. Later, another part of the application retrieves this data and uses it unsafely in an SQL query
3. The malicious payload executes in this second context

## Example Scenario

```sql
-- First interaction (storing data)
INSERT INTO user_comments (user_id, comment) 
VALUES (123, 'Harmless comment'); DROP TABLE users; --');

-- Second interaction (triggering the attack)
SELECT comment FROM user_comments WHERE user_id = 123;
-- The application might concatenate this directly into another query
```

## Prevention Methods

1. **Parameterized Queries**: Use for all database interactions, including those using stored data
2. **Input Validation**: Validate both at input time and when retrieving stored data
3. **Output Encoding**: Encode data appropriately when retrieving from storage
4. **Least Privilege**: Database accounts should have minimal necessary permissions
5. **Static Analysis**: Use tools to detect potential second-order vulnerabilities

## Detection Challenges

- Harder to detect than first-order injections because:
  - The vulnerability spans multiple application flows
  - Static analysis tools may miss the connection between storage and usage
  - Testing requires multi-step test cases