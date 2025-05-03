import aiohttp
import asyncio
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fetch")

async def fetch(session, url, proxy=None, timeout=10, retries=3, backoff=2):
    delay = 1
    for attempt in range(1, retries + 1):
        try:
            async with session.get(url, proxy=proxy, timeout=timeout) as response:
                text = await response.text()
                logger.info(f"Fetched {url} [Status: {response.status}]")
                return text
        except Exception as e:
            logger.warning(f"Attempt {attempt}: Failed to fetch {url} — {e}")
            if attempt < retries:
                await asyncio.sleep(delay)
                delay *= backoff  # exponential backoff
    return None
