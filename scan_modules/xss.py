from payloads.xss_payloads import xss_payloads
import aiohttp

async def scan_xss(session, url):
    results = []
    for payload in xss_payloads:
        test_url = f"{url}?q={payload}"
        try:
            async with session.get(test_url, timeout=10) as response:
                text = await response.text()
                if payload in text:
                    results.append((test_url, "Possible XSS"))
        except Exception:
            continue
    return results
