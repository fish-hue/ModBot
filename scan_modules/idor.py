from payloads.idor_payloads import idor_payloads
import aiohttp
import logging

async def scan_idor(session, url, proxy):
    results = []
    for payload in idor_payloads:
        test_url = f"{url}?user_id={payload}"  # Attempting to modify user_id
        try:
            async with session.get(test_url, timeout=10) as response:
                text = await response.text()
                if "Unauthorized" not in text:  # If access is not denied
                    results.append((test_url, "Possible Broken Access Control (IDOR)"))
                    logging.info(f"IDOR vulnerability detected: {test_url}")
        except Exception as e:
            logging.error(f"Error testing {test_url}: {e}")
            continue
    return results
