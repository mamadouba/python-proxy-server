
import asyncio 
import aiohttp

urls = (
    'http://cnn.com',
    'http://nytimes.com',
    'http://google.com',
    'http://leagueoflegends.com',
    'http://python.org',
)
async def download(session, url):
    print(f"Started download {url}")
    async with session.get(url) as response:
        return url, await response.read()

async def download_all():
    async with aiohttp.ClientSession() as session:
        tasks = [download(session, url) for url in urls]
        for task in asyncio.as_completed(tasks):
            url, data = await task
            print(f"Finished download {url}")
asyncio.run(download_all())
