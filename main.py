import asyncio
import argparse
import aiohttp

from scan_modules.sql_injection import scan_sql_injection
from scan_modules.xss import scan_xss
from scan_modules.cmdi import scan_cmdi
from scan_modules.traversal import scan_traversal
from scan_modules.idor import scan_idor

async def main_scan(url, session):
    results = []
    if should_scan_idor:  # Assuming should_scan_idor is determined by user input in the GUI or CLI
        idor_results = await scan_idor(session, url)
        results.extend(idor_results)

    # Include other scans (XSS, SQLi, etc.)
    return results

async def run_scans(url):
    async with aiohttp.ClientSession() as session:
        print("[*] Starting vulnerability scans...")
        results = []
        results += await scan_sql_injection(session, url)
        results += await scan_xss(session, url)
        results += await scan_cmdi(session, url)
        results += await scan_traversal(session, url)
        
        if results:
            for r in results:
                print(f"[!] {r[1]} at {r[0]}")
        else:
            print("[+] No vulnerabilities found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Async Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan (e.g., http://example.com/page)")
    args = parser.parse_args()

    asyncio.run(run_scans(args.url))
