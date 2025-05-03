from payloads.sql_payloads import sql_payloads
import aiohttp

async def scan_sql_injection(session, url):
    results = []
    error_keywords = ['sql', 'syntax', 'mysql']  # keywords to search for in response text

    for payload in sql_payloads:
        test_url = f"{url}?input={payload}"
        try:
            async with session.get(test_url, timeout=10) as response:
                text = await response.text()
                text_lower = text.lower()  # Convert once for all checks
                if any(keyword in text_lower for keyword in error_keywords):
                    results.append((test_url, "Possible SQL Injection"))
        except aiohttp.ClientError:
            continue  # Handle specific exceptions like client errors to avoid catching unrelated issues
    return results
