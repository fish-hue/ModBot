from payloads.cmdi_payloads import cmdi_payloads
import aiohttp

async def scan_cmdi(session, url):
    results = []
    for payload in cmdi_payloads:
        test_url = f"{url}?cmd={payload}"
        try:
            async with session.get(test_url, timeout=10) as response:
                text = await response.text()
                if "uid=" in text or "root" in text:
                    results.append((test_url, "Possible Command Injection"))
        except Exception:
            continue
    return results
