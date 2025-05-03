from payloads.idor_payloads import idor_payloads
import aiohttp
import logging
import asyncio # Import asyncio

async def scan_idor(session, url, proxy, stop_event=None): # Added stop_event=None
    results = []
    for payload in idor_payloads:
        if stop_event and stop_event.is_set(): # Check the stop event
            print("IDOR scan stopping...") # Optional: Add a message for feedback
            break  # Exit the loop if the stop flag is set

        test_url = f"{url}?user_id={payload}"  # Attempting to modify user_id
        try:
            # You might want to include the proxy here if you're using one
            async with session.get(test_url, timeout=10, proxy=proxy) as response:
                if stop_event and stop_event.is_set(): # Check again after the request
                    print("IDOR scan stopping after request...") # Optional feedback
                    break # Exit the loop if the stop flag is set

                text = await response.text()
                if "Unauthorized" not in text and response.status != 401 and response.status != 403:  # If access is not explicitly denied (consider status codes too)
                    results.append((test_url, "Possible Broken Access Control (IDOR)"))
                    logging.info(f"IDOR vulnerability detected: {test_url}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            # Handle specific aiohttp and asyncio errors
            logging.warning(f"Request error for {test_url}: {e}")
        except Exception as e:
            # Catch any other unexpected errors
            logging.error(f"Unexpected error testing {test_url}: {e}")
        # continue is not strictly needed here, the loop will naturally go to the next iteration

    return results
