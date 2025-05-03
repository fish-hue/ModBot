from payloads.traversal_payloads import traversal_payloads
import aiohttp
import asyncio
import re
import logging
import csv

# Set up logging (assuming this is done once in your main script or __init__)
# If not, keep these lines:
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# logger = logging.getLogger(__name__)

# Compiled regular expressions for quicker checks
TRAVERSAL_SIGNATURES = [re.compile(r"root:"), re.compile(r"\[extensions\]")]

async def scan_traversal(session, url, proxy, stop_event=None, save_to_file=False): # Added proxy and stop_event
    results = []
    tasks = []

    for payload in traversal_payloads:
        if stop_event and stop_event.is_set(): # Check stop event before creating new tasks
            logging.info("Directory Traversal scan stopping (before creating tasks)...")
            break  # Stop creating new tasks if the stop flag is set

        # Pass the stop_event to the single scan task
        tasks.append(scan_single_traversal(session, url, proxy, payload, stop_event))

    # Await results for all tasks concurrently, handling potential cancellation
    try:
        responses = await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        logging.info("Directory Traversal scan was cancelled.")
        responses = [] # Or handle partially completed results if needed

    # Process the results
    for result in responses:
        # Filter out exceptions and None results
        if isinstance(result, tuple) and len(result) == 2: # Check if it's a (url, message) tuple
             results.append(result)
        elif isinstance(result, Exception):
             logging.error(f"Error in a scan_single_traversal task: {result}")
        # None results are handled by the check above

    # Log any non-vulnerable responses (consider if this is still needed with the new structure)
    # log_non_vulnerable(responses) # This function might need adjustment or removal

    # Save the results to a CSV file if requested
    if save_to_file:
        save_results_to_csv(results)

    return results

async def scan_single_traversal(session, url, proxy, payload, stop_event=None): # Added proxy and stop_event
    if stop_event and stop_event.is_set():
        logging.info(f"Directory Traversal task for payload {payload} stopping (at start)...")
        return None # Return None if stopping before the request

    test_url = f"{url}?file={payload}"
    try:
        # Include proxy in the request
        async with session.get(test_url, timeout=10, proxy=proxy) as response:
            if stop_event and stop_event.is_set():
                logging.info(f"Directory Traversal task for payload {payload} stopping (after request)...")
                return None # Return None if stopping after the request

            text = await response.text()

            # Check for traversal vulnerabilities by matching compiled regex patterns
            if any(regex.search(text) for regex in TRAVERSAL_SIGNATURES):
                return (test_url, "Possible Directory Traversal")

            # If no vulnerability found, log the failed response
            logging.info(f"Failed: {test_url} - No directory traversal vulnerability detected.")

    except asyncio.CancelledError:
        # Explicitly handle cancellation for this task
        logging.info(f"Directory Traversal task for payload {payload} was cancelled.")
        raise # Re-raise the cancellation error to be caught by asyncio.gather
    except aiohttp.ClientError as e:
        # Log the specific error (e.g., connection failure)
        logging.error(f"Error fetching {test_url}: {str(e)}")
        return None # Return None on error
    except Exception as e:
        # Catch any other unexpected errors
        logging.error(f"Unexpected error testing {test_url}: {e}")
        return None # Return None on unexpected error

    return None # Return None if no vulnerability is found

# The log_non_vulnerable and save_results_to_csv functions remain the same
# but consider if log_non_vulnerable is still useful or needs modification
# given the improved logging in scan_single_traversal.

def log_non_vulnerable(responses):
    # Log non-vulnerable responses or failed attempts
    # This function might need adjustment or removal
    # based on how you want to log non-vulnerable outcomes now.
    # The logging is already happening in scan_single_traversal.
    pass # You might want to remove or modify this function

def save_results_to_csv(results, filename='scan_results.csv'):
    # Save results to a CSV file
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as file: # Added encoding
            writer = csv.writer(file)
            # Write the header
            writer.writerow(['URL', 'Vulnerability Type'])
            # Write the scan results
            for result in results:
                writer.writerow(result)

        logging.info(f"Scan results saved to {filename}")
    except IOError as e:
        logging.error(f"Error saving results to {filename}: {e}")


# Assuming these are defined elsewhere or you want to keep them here
# from payloads.traversal_payloads import traversal_payloads
# from utils.http import fetch # Note: This module doesn't use your fetch function directly anymore,
# it uses aiohttp.ClientSession.get

# If you want to use your fetch function, you would modify scan_single_traversal to use it.
# Example using fetch:
# async def scan_single_traversal(session, url, proxy, payload, stop_event=None):
#     if stop_event and stop_event.is_set():
#         logging.info(f"Directory Traversal task for payload {payload} stopping (at start)...")
#         return None
#
#     test_url = f"{url}?file={payload}"
#     try:
#         text = await fetch(session, test_url, proxy=proxy, timeout=10) # Assuming fetch supports timeout and proxy
#
#         if stop_event and stop_event.is_set():
#              logging.info(f"Directory Traversal task for payload {payload} stopping (after fetch)...")
#              return None
#
#         if text: # Check if fetch returned text (assuming None on error)
#             text_lower = text.lower()
#             if any(regex.search(text_lower) for regex in TRAVERSAL_SIGNATURES):
#                 return (test_url, "Possible Directory Traversal")
#
#             logging.info(f"Failed: {test_url} - No directory traversal vulnerability detected.")
#
#     except asyncio.CancelledError:
#         logging.info(f"Directory Traversal task for payload {payload} was cancelled.")
#         raise
#     except Exception as e: # Catch any exception from fetch or processing
#         logging.error(f"Error testing {test_url}: {e}")
#         return None
#
#     return None
