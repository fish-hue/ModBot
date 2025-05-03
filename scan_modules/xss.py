from payloads.xss_payloads import xss_payloads
import aiohttp

async def scan_xss(session, url):
    results = []
    tasks = []
    
    # Prepare tasks for asynchronous execution
    for payload in xss_payloads:
        test_url = f"{url}?q={payload}"
        tasks.append(scan_task(session, test_url, payload))
    
    # Run all tasks concurrently
    responses = await asyncio.gather(*tasks)
    
    # Collect results that matched XSS indicators
    for response in responses:
        if response:
            results.append(response)
    
    return results

async def scan_task(session, test_url, payload):
    try:
        async with session.get(test_url, timeout=10) as response:
            text = await response.text()
            if payload in text or "<script>" in text.lower() or "javascript:" in text.lower():
                return (test_url, "Possible XSS")
    except aiohttp.ClientError:
        # Log or handle client errors specifically
        return None
    except Exception:
        # Handle other errors (e.g., timeout, etc.)
        return None
