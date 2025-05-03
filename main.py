import asyncio
import argparse
import aiohttp

from scan_modules.sql_injection import scan_sql_injection
from scan_modules.xss import scan_xss
from scan_modules.cmdi import scan_cmdi
from scan_modules.traversal import scan_traversal
from scan_modules.idor import scan_idor

async def run_scans(url, proxy=None, include_idor=False):
    async with aiohttp.ClientSession() as session:
        print("[*] Starting vulnerability scans...")
        results = []

        # Run the scans with proxy if provided
        results += await scan_sql_injection(session, url, proxy)
        results += await scan_xss(session, url, proxy)
        results += await scan_cmdi(session, url, proxy)
        results += await scan_traversal(session, url, proxy)

        # Include the IDOR scan if requested
        if include_idor:
            results += await scan_idor(session, url, proxy)

        # Print results
        if results:
            for r in results:
                print(f"[!] {r[1]} at {r[0]}")
        else:
            print("[+] No vulnerabilities found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ModBot Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan (e.g., http://example.com/page)")
    parser.add_argument("--scan-idor", action="store_true", help="Include IDOR (Broken Access Control) scan")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)
    args = parser.parse_args()

    asyncio.run(run_scans(args.url, proxy=args.proxy, include_idor=args.scan_idor))
