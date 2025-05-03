import aiohttp
import asyncio
import re
import logging
import csv
from payloads.traversal_payloads import traversal_payloads

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Compiled regular expressions for quicker checks
TRAVERSAL_SIGNATURES = [re.compile(r"root:"), re.compile(r"\[extensions\]")]

async def scan_traversal(session, url, save_to_file=False):
    results = []
    # Prepare all test URLs in advance for efficient async handling
    tasks = [scan_single_traversal(session, url, payload) for payload in traversal_payloads]
    
    # Await results for all tasks concurrently
    responses = await asyncio.gather(*tasks)
    
    # Process the results
    for result in responses:
        if result:
            results.append(result)

    # Log any non-vulnerable responses
    log_non_vulnerable(responses)

    # Save the results to a CSV file if requested
    if save_to_file:
        save_results_to_csv(results)
    
    return results

async def scan_single_traversal(session, url, payload):
    test_url = f"{url}?file={payload}"
    try:
        async with session.get(test_url, timeout=10) as response:
            text = await response.text()

            # Check for traversal vulnerabilities by matching compiled regex patterns
            if any(regex.search(text) for regex in TRAVERSAL_SIGNATURES):
                return (test_url, "Possible Directory Traversal")
            
            # If no vulnerability found, log the failed response
            logger.info(f"Failed: {test_url} - No directory traversal vulnerability detected.")

    except aiohttp.ClientError as e:
        # Log the specific error (e.g., connection failure)
        logger.error(f"Error fetching {test_url}: {str(e)}")

    return None

def log_non_vulnerable(responses):
    # Log non-vulnerable responses or failed attempts
    for response in responses:
        if response is None:
            logger.info("No vulnerability detected for one of the payloads.")

def save_results_to_csv(results, filename='scan_results.csv'):
    # Save results to a CSV file
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        # Write the header
        writer.writerow(['URL', 'Vulnerability Type'])
        # Write the scan results
        for result in results:
            writer.writerow(result)
    
    logger.info(f"Scan results saved to {filename}")
