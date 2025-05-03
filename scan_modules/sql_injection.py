from payloads.sql_payloads import sql_payloads
from utils.http import fetch
import asyncio # Import asyncio
import logging # Import logging if fetch uses it, or for general use

async def scan_sql_injection(session, url, proxy=None, stop_event=None): # Added stop_event=None
    results = []
    error_keywords = ['sql', 'syntax', 'mysql', 'error'] # Added 'error' as a common keyword

    for payload in sql_payloads:
        if stop_event and stop_event.is_set(): # Check the stop event before fetching
            print("SQL Injection scan stopping...") # Optional feedback
            break  # Exit the loop if the stop flag is set

        test_url = f"{url}?input={payload}"
        # Assuming fetch handles errors internally and returns None or raises exceptions
        text = await fetch(session, test_url, proxy=proxy)

        if stop_event and stop_event.is_set(): # Check again after fetching
             print("SQL Injection scan stopping after fetch...") # Optional feedback
             break # Exit the loop if the stop flag is set

        if text:
            text_lower = text.lower()
            if any(keyword in text_lower for keyword in error_keywords):
                results.append((test_url, "Possible SQL Injection"))
                logging.info(f"SQL Injection vulnerability detected: {test_url}") # Example logging

    return results
