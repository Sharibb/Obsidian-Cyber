

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

## Detection