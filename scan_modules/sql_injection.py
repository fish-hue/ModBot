from payloads.sql_payloads import sql_payloads
import aiohttp

async def scan_sql_injection(session, url):
    results = []
    for payload in sql_payloads:
        test_url = f"{url}?input={payload}"
        try:
            async with session.get(test_url, timeout=10) as response:
                text = await response.text()
                if "SQL" in text or "syntax" in text or "mysql" in text.lower():
                    results.append((test_url, "Possible SQL Injection"))
        except Exception as e:
            continue
    return results
