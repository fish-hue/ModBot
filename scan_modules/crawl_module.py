# crawl_module.py
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin

async def crawl_for_files(url, file_extensions=None):
    if file_extensions is None:
        file_extensions = [
            ".pdf", ".mp3", ".jpeg", ".jpg", ".png", ".txt", ".zip", ".tar", ".gz",
            ".rar", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv",
            ".json", ".xml", ".apk", ".exe", ".tar.gz", ".7z", ".mp4", ".mkv",
            ".avi", ".webm", ".flv", ".bmp", ".svg", ".css", ".js"
        ]

    files = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                soup = BeautifulSoup(await response.text(), "html.parser")

                # Find all anchor tags (<a>) with href attributes
                for link in soup.find_all("a", href=True):
                    href = link['href']
                    # Check if the link ends with any of the specified file extensions
                    if any(href.endswith(ext) for ext in file_extensions):
                        full_url = urljoin(url, href)
                        files.append(full_url)

    except aiohttp.ClientError as e:
        print(f"Error during HTTP request for {url}: {e}")
    except Exception as e:
        print(f"Error crawling {url}: {e}")

    return files
