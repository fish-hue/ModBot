import aiohttp
from payloads.cmdi_payloads import cmdi_payloads

async def scan_cmdi(session, url, proxy):
    results = []
    tasks = []

    # Prepare the URL with the command injection payloads.
    for payload in cmdi_payloads:
        test_url = f"{url}?cmd={payload}"
        tasks.append(scan_single_cmdi(session, test_url, payload, results))

    # Use asyncio.gather to run the scan concurrently.
    await asyncio.gather(*tasks)

    return results

async def scan_single_cmdi(session, test_url, payload, results):
    try:
        async with session.get(test_url, timeout=10) as response:
            text = await response.text()
            if "uid=" in text or "root" in text:
                results.append((test_url, "Possible Command Injection"))
    except aiohttp.ClientError as e:
        # Handle aiohttp specific errors.
        pass
    except asyncio.TimeoutError:
        # Handle timeout errors specifically.
        pass
    except Exception:
        # Catch other unexpected exceptions, but leave them unhandled for now.
        pass
