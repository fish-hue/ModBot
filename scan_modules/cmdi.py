import aiohttp
import asyncio
from payloads.cmdi_payloads import cmdi_payloads

async def scan_cmdi(session, url, proxy=None, stop_event=None):
    results = []
    tasks = []

    # Prepare the URL with the command injection payloads.
    for payload in cmdi_payloads:
        if stop_event and stop_event.is_set():
            break  # Stop scanning early if stop_event is set
        test_url = f"{url}?cmd={payload}"
        tasks.append(scan_single_cmdi(session, test_url, payload, results, stop_event))

    # Run all tasks concurrently
    await asyncio.gather(*tasks, return_exceptions=True)

    return results

async def scan_single_cmdi(session, test_url, payload, results, stop_event=None):
    if stop_event and stop_event.is_set():
        return

    try:
        async with session.get(test_url, timeout=10) as response:
            if stop_event and stop_event.is_set():
                return
            text = await response.text()
            if "uid=" in text or "root" in text:
                results.append((test_url, "Possible Command Injection"))
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    except Exception:
        pass
