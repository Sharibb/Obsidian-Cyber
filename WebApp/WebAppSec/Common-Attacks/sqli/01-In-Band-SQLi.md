

# In-Band SQL Injection (SQLi)

In-Band SQL Injection is one of the most common and straightforward types of SQL injection attacks where the attacker uses the same communication channel to both launch the attack and gather results.

## Types of In-Band SQLi:

1. **Error-Based SQLi**:
   - Relies on error messages returned by the database server
   - Attacker intentionally causes errors to extract information
   - Example: `' OR 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--`

2. **Union-Based SQLi**:
   - Uses the UNION SQL operator to combine results from multiple SELECT statements
   - Requires knowledge of the database structure
   - Example: `' UNION SELECT username, password FROM users--`

## Characteristics:
- Results are returned directly in the application's response
- Easier to exploit than other types (blind SQLi)
- Often used for data extraction

## Prevention:
- Use parameterized queries/prepared statements
- Implement proper error handling (don't show DB errors to users)
- Apply principle of least privilege for DB accounts
- Use web application firewalls (WAFs)

Explain Error Based and Union Based a bit more in depth

 