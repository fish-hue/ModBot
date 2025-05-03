from payloads.xss_payloads import xss_payloads
import aiohttp
import asyncio # Import asyncio
import logging # Import logging for potential use

# Assuming logging is set up elsewhere in your main script or __init__
# If not, you might want to add:
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# logger = logging.getLogger(__name__) # Define a logger if needed

async def scan_xss(session, url, proxy, stop_event=None): # Added proxy and stop_event
    results = []
    tasks = []

    for payload in xss_payloads:
        if stop_event and stop_event.is_set(): # Check stop event before creating new tasks
            logging.info("XSS scan stopping (before creating tasks)...") # Optional feedback
            break  # Stop creating new tasks if the stop flag is set

        test_url = f"{url}?q={payload}"
        # Pass the stop_event to the single scan task
        tasks.append(scan_single_xss(session, test_url, payload, proxy, stop_event)) # Renamed scan_task to scan_single_xss and added proxy

    # Run all tasks concurrently, handling potential cancellation
    try:
        responses = await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        logging.info("XSS scan was cancelled.")
        responses = [] # Or handle partially completed results if needed

    # Collect results that matched XSS indicators
    for response in responses:
        # Filter out exceptions and None results
        if isinstance(response, tuple) and len(response) == 2: # Check if it's a (url, message) tuple
             results.append(response)
        elif isinstance(response, Exception):
             logging.error(f"Error in a scan_single_xss task: {response}")
        # None results are handled by the check above

    return results

async def scan_single_xss(session, test_url, payload, proxy, stop_event=None): # Added proxy and stop_event, Renamed from scan_task
    if stop_event and stop_event.is_set():
        logging.info(f"XSS task for payload {payload} stopping (at start)...") # Optional feedback
        return None # Return None if stopping before the request

    try:
        # Include proxy in the request
        async with session.get(test_url, timeout=10, proxy=proxy) as response:
            if stop_event and stop_event.is_set(): # Check again after the request
                logging.info(f"XSS task for payload {payload} stopping (after request)...") # Optional feedback
                return None # Return None if stopping after the request

            text = await response.text()
            if payload in text or "<script>" in text.lower() or "javascript:" in text.lower():
                logging.info(f"Possible XSS detected: {test_url}") # Example logging
                return (test_url, "Possible XSS")

    except asyncio.CancelledError:
        # Explicitly handle cancellation for this task
        logging.info(f"XSS task for payload {payload} was cancelled.") # Optional feedback
        raise # Re-raise the cancellation error to be caught by asyncio.gather
    except aiohttp.ClientError as e:
        # Log or handle client errors specifically
        logging.warning(f"Request error for {test_url}: {e}") # Use warning for client errors
        return None
    except Exception as e:
        # Handle other errors (e.g., timeout, etc.)
        logging.error(f"Unexpected error testing {test_url}: {e}")
        return None

    return None # Return None if no vulnerability is found for this payload
