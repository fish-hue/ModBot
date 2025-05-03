from payloads.traversal_payloads import traversal_payloads
import aiohttp

async def scan_traversal(session, url):
    results = []
    for payload in traversal_payloads:
        test_url = f"{url}?file={payload}"
        try:
            async with session.get(test_url, timeout=10) as response:
                text = await response.text()
                if "root:" in text or "[extensions]" in text:
                    results.append((test_url, "Possible Directory Traversal"))
        except Exception:
            continue
    return results
