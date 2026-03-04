import aiohttp
import random
import asyncio


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
]


class AsyncCrawler:

    def __init__(self, concurrency=20):

        self.connector = aiohttp.TCPConnector(
            limit=concurrency,
            ssl=True
        )

    # ------------------------------------------------
    # Fetch function
    # ------------------------------------------------

    async def fetch(self, session, url, retries=2):

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive"
        }

        for attempt in range(retries + 1):

            try:

                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True
                ) as response:

                    status = response.status
                    content_type = response.headers.get("Content-Type", "").lower()

                    print(f"[FETCH] {url} → {status}")

                    if status >= 400:
                        return url, None, content_type

                    # Skip very large responses
                    content_length = response.headers.get("Content-Length")
                    if content_length and int(content_length) > 5_000_000:
                        print(f"[SKIP] Large file {url}")
                        return url, None, content_type

                    try:
                        text = await response.text(errors="ignore")
                    except Exception:
                        text = None

                    return url, text, content_type

            except asyncio.TimeoutError:
                print(f"[TIMEOUT] {url}")

            except aiohttp.ClientConnectionError:
                print(f"[CONNECTION ERROR] {url}")

            except aiohttp.ClientPayloadError:
                print(f"[PAYLOAD ERROR] {url}")

            except Exception as e:
                print(f"[ERROR] {url} -> {e}")

            await asyncio.sleep(1)

        return url, None, None

    # ------------------------------------------------
    # Crawl multiple URLs
    # ------------------------------------------------

    async def crawl(self, urls):

        async with aiohttp.ClientSession(connector=self.connector) as session:

            tasks = [
                self.fetch(session, url)
                for url in urls
            ]

            return await asyncio.gather(*tasks)