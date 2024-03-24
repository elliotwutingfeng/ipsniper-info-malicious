"""Extract malicious URLs found at https://ipsniper.info
and write them to a .txt blocklist
"""
import asyncio
import logging
import re
import datetime

import aiohttp
from bs4 import BeautifulSoup, SoupStrainer

logger = logging.getLogger()
logging.basicConfig(level=logging.INFO, format="%(message)s")


default_headers: dict = {
    "Content-Type": "application/json",
    "Connection": "keep-alive",
    "Cache-Control": "no-cache",
    "Accept": "*/*",
}


async def backoff_delay_async(backoff_factor: float, number_of_retries_made: int) -> None:
    """Asynchronous time delay that exponentially increases with `number_of_retries_made`

    Args:
        backoff_factor (float): Backoff delay multiplier
        number_of_retries_made (int): More retries made -> Longer backoff delay
    """
    await asyncio.sleep(backoff_factor * (2 ** (number_of_retries_made - 1)))


async def get_async(
    endpoints: list[str], max_concurrent_requests: int = 5, headers: dict = None
) -> dict[str, bytes]:
    """Given a list of HTTP endpoints, make HTTP GET requests asynchronously

    Args:
        endpoints (list[str]): List of HTTP GET request endpoints
        max_concurrent_requests (int, optional): Maximum number of concurrent async HTTP requests.
        Defaults to 5.
        headers (dict, optional): HTTP Headers to send with every request. Defaults to None.

    Returns:
        dict[str,bytes]: Mapping of HTTP GET request endpoint to its HTTP response content. If
        the GET request failed, its HTTP response content will be `b"{}"`
    """
    if headers is None:
        headers = default_headers

    async def gather_with_concurrency(max_concurrent_requests: int, *tasks) -> dict[str, bytes]:
        semaphore = asyncio.Semaphore(max_concurrent_requests)

        async def sem_task(task):
            async with semaphore:
                await asyncio.sleep(0.5)
                return await task

        tasklist = [sem_task(task) for task in tasks]
        return dict([await f for f in asyncio.as_completed(tasklist)])

    async def get(url, session):
        max_retries: int = 5
        errors: list[str] = []
        for number_of_retries_made in range(max_retries):
            try:
                async with session.get(url, headers=headers) as response:
                    return (url, await response.read())
            except Exception as error:
                errors.append(repr(error))
                logger.warning("%s | Attempt %d failed", error, number_of_retries_made + 1)
                if number_of_retries_made != max_retries - 1:  # No delay if final attempt fails
                    await backoff_delay_async(1, number_of_retries_made)
        logger.error("URL: %s GET request failed! Errors: %s", url, errors)
        return (url, b"{}")  # Allow json.loads to parse body if request fails

    # GET request timeout of 5 minutes (300 seconds)
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=0, ttl_dns_cache=300),
        raise_for_status=True,
        timeout=aiohttp.ClientTimeout(total=300),
    ) as session:
        # Only one instance of any duplicate endpoint will be used
        return await gather_with_concurrency(
            max_concurrent_requests, *[get(url, session) for url in set(endpoints)]
        )


def get_recursively(search_dict: dict, field: str) -> list:
    """Take a dict with nested lists and dicts,
    and searche all dicts for a key of the field
    provided.

    https://stackoverflow.com/a/20254842

    Args:
        search_dict (dict): Dictionary to search
        field (str): Field to search for

    Returns:
        list: List of values of field
    """
    fields_found = []

    for key, value in search_dict.items():

        if key == field:
            fields_found.append(value)

        elif isinstance(value, dict):
            results = get_recursively(value, field)
            for result in results:
                fields_found.append(result)

        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    more_results = get_recursively(item, field)
                    for another_result in more_results:
                        fields_found.append(another_result)

    return fields_found


def current_datetime_str() -> str:
    """Current time's datetime string in UTC.

    Returns:
        str: Timestamp in strftime format "%d_%b_%Y_%H_%M_%S-UTC"
    """
    return datetime.datetime.now(datetime.UTC).strftime("%d_%b_%Y_%H_%M_%S-UTC")


def clean_url(url: str) -> str:
    """Remove zero width spaces, leading/trailing whitespaces, trailing slashes,
    and URL prefixes from a URL

    Args:
        url (str): URL

    Returns:
        str: URL without zero width spaces, leading/trailing whitespaces, trailing slashes,
    and URL prefixes
    """
    removed_zero_width_spaces = re.sub(r"[\u200B-\u200D\uFEFF]", "", url)
    removed_leading_and_trailing_whitespaces = removed_zero_width_spaces.strip()
    removed_trailing_slashes = removed_leading_and_trailing_whitespaces.rstrip("/")
    removed_https = re.sub(r"^[Hh][Tt][Tt][Pp][Ss]:\/\/", "", removed_trailing_slashes)
    removed_http = re.sub(r"^[Hh][Tt][Tt][Pp]:\/\/", "", removed_https)

    return removed_http


async def extract_urls() -> set[str]:
    """Extract malicious URLs found at ipsniper.info

    Returns:
        set[str]: Unique malicious URLs
    """
    try:
        # main page
        endpoint: str = "https://ipsniper.info/malicious_domains"
        main_page = (await get_async([endpoint]))[endpoint]

        # <a> tags
        a_strainer = SoupStrainer("a")

        soup = BeautifulSoup(main_page, "lxml", parse_only=a_strainer)

        if a_tags := soup.find_all(
            lambda tag: tag.string is not None and tag.string.endswith(".txt")
        ):
            filenames = sorted(
                re.sub(r"[\u200B-\u200D\uFEFF]", "", a_tag.string) for a_tag in a_tags
            )
            if filenames:
                latest_filename = filenames[-1]
            else:
                raise ValueError("No .txt files found")

            feed_url = f"{endpoint}/{latest_filename}"

            feed_contents = (await get_async([feed_url]))[feed_url]

            if feed_contents != b"{}":
                # Extract URLs
                urls = feed_contents.decode().splitlines()
                return set(clean_url(url) for url in urls)
            else:
                raise ValueError("Failed to retrieve content from .txt file")
        else:
            logger.error("No <a> tags found")
            return set()
    except Exception as error:
        logger.error(error)
        return set()


if __name__ == "__main__":
    urls: set[str] = asyncio.run(extract_urls())
    if not urls:
        raise ValueError("Failed to scrape URLs")
    timestamp: str = current_datetime_str()
    filename = "ipsniper-info-malicious-urls.txt"
    with open(filename, "w") as f:
        f.writelines("\n".join(sorted(urls)))
        logger.info("%d URLs written to %s at %s", len(urls), filename, timestamp)
