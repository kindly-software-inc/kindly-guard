# SQL Database Tutorial

This tutorial covers basic SQL commands and best practices.

## SELECT Statement

The SELECT statement is used to query data from a database. Here's the basic syntax:

```sql
SELECT column1, column2 FROM table_name WHERE condition;
```

## Security Best Practices

To prevent SQL injection attacks, always use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.

### Bad Example (Vulnerable):
```python
query = "SELECT * FROM users WHERE username = '" + user_input + "'"
```

### Good Example (Safe):
```python
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (user_input,))
```

## HTML and JavaScript

When working with web applications, be aware of XSS vulnerabilities. The `<script>` tag can execute JavaScript code, so always escape user input before displaying it in HTML.

## Command Line Tools

Common Unix commands like `rm`, `cat`, and `grep` are powerful but should be used carefully. The command `rm -rf /` would delete everything on a Unix system if run with sufficient privileges (never run this!).

## LDAP Queries

LDAP uses a specific filter syntax with parentheses. For example:
- `(objectClass=user)` - Find all user objects
- `(&(objectClass=user)(cn=John*))` - Find users whose names start with John

Remember: This is educational content about security, not actual attack code.