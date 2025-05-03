from payloads.sql_payloads import sql_payloads
from utils.http import fetch

async def scan_sql_injection(session, url, proxy=None):
    results = []
    error_keywords = ['sql', 'syntax', 'mysql']

    for payload in sql_payloads:
        test_url = f"{url}?input={payload}"
        text = await fetch(session, test_url, proxy=proxy)
        if text:
            text_lower = text.lower()
            if any(keyword in text_lower for keyword in error_keywords):
                results.append((test_url, "Possible SQL Injection"))

    return results

