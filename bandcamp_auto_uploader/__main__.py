import http.cookiejar
import logging
import sys
from importlib.metadata import version
from pathlib import Path
from typing import Optional

import requests
from browser_cookie3 import (
    BrowserCookieError,
    brave,
    chrome,
    chromium,
    edge,
    firefox,
    opera,
    opera_gx,
    safari,
    vivaldi,
)
from InquirerPy import inquirer
from rich import print
from rich.markup import escape

from bandcamp_auto_uploader.bandcamp_http_adapter import BandcampHTTPAdapter
from bandcamp_auto_uploader.config import (
    get_config_file_path,
    init_config,
    load_config,
    save_config,
)
from bandcamp_auto_uploader.upload import Album

__version__ = version("bandcamp_auto_uploader")

logger = logging.getLogger("bandcamp-auto-uploader")


def get_owned_bands(cj: http.cookiejar.CookieJar):
    session = requests.Session()
    session.mount("https://", BandcampHTTPAdapter())
    session.cookies.update(cj)
    r = session.post("https://bandcamp.com/api/design_system/1/menubar")
    logger.debug(f"Page text: {r.text}")
    r.raise_for_status()
    data = r.json()
    bands = [data.get("activeBand")]

    # this is untested
    if data.get("labelBands"):
        bands.extend(data["labelBands"])
    if data.get("additionalLabelBands"):
        bands.extend(data["additionalLabelBands"])

    band_urls = []
    for band in bands:
        if not band:
            continue
        try:
            band_urls.append(band["url"])
        except Exception as ex:
            logger.info(ex)
    return list(set(band_urls))


def try_get_owned_bands_from_cookies_file(
    cookies_file: str,
) -> Optional[dict[str, http.cookiejar.CookieJar]]:
    print(f"[yellow]Loading cookies from {escape(cookies_file)}[/]")
    try:
        cj = http.cookiejar.MozillaCookieJar(cookies_file)
        cj.load()
        logger.debug("Cookies:")
        for cookie in cj:
            logger.debug(f"    {cookie.domain}: {cookie.name}")
        return {url: cj for url in get_owned_bands(cj)}
    except Exception as ex:
        logger.exception(ex)
        return None


def try_get_owned_bands_from_browsers() -> Optional[
    dict[str, http.cookiejar.CookieJar]
]:
    print("[yellow]Loading cookies from browsers[/]")
    try:
        url_to_cj = {}
        for cookie_fn in [
            brave,
            chrome,
            chromium,
            edge,
            firefox,
            opera,
            opera_gx,
            safari,
            vivaldi,
        ]:
            cj = http.cookiejar.CookieJar()
            try:
                logged_in = False
                for cookie in cookie_fn(domain_name="bandcamp.com"):
                    cj.set_cookie(cookie)
                    if cookie.name == "js_logged_in" and cookie.value == "1":
                        logged_in = True
                if not logged_in:
                    continue
                for url in get_owned_bands(cj):
                    logger.info(f"[{cookie_fn.__name__}] Found band: {url}")
                    url_to_cj[url] = cj
            except BrowserCookieError:
                pass
            except Exception as ex:
                logger.debug("Cookie load error", exc_info=ex)
                logger.error(
                    f"[{cookie_fn.__name__}] Failed to get cookies from browser"
                )
        return url_to_cj
    except Exception as ex:
        logger.exception(ex)
        print("[bold red]Could not automatically get cookies[/]")
        return None


def main():
    def path_filter(path: str) -> Path:
        return Path(path.strip("\"'& "))

    def dir_path_validator(path_str: str):
        path = path_filter(path_str)
        return path.exists() and path.is_dir()

    def file_path_validator(path_str: str):
        path = path_filter(path_str)
        return path.exists() and not path.is_dir()

    print("-" * 40)
    print(
        f"[bold purple]bandcamp-auto-uploader[/] [bold blue]{__version__}[/] by [green underline link=https://github.com/7x11x13]7x11x13[/]"
    )
    print("-" * 40)

    config = load_config()
    if config is None:
        print("[bold yellow]No config file detected. Launching first time setup...[/]")
        config = init_config()
        print("[bold green]Config saved![/]")
    else:
        print(
            f"[bold green]Config loaded from {escape(str(get_config_file_path()))}[/]"
        )
    save_config(config)

    if config.debug:
        logger.setLevel(logging.DEBUG)

    urls = None
    if config.cookies_file:
        urls = try_get_owned_bands_from_cookies_file(config.cookies_file)
        if urls is None:
            print(
                "[bold red]Could not load cookies file, trying to automatically get cookies[/]"
            )

    if urls is None:
        urls = try_get_owned_bands_from_browsers()
        while urls is None:
            cookies_path = inquirer.filepath(
                message="Enter path to bandcamp cookies.txt file (or drag and drop file here)",
                validate=file_path_validator,
                filter=path_filter,
                invalid_message="Path must be to an existing file",
            ).execute()
            config.cookies_file = str(cookies_path.resolve())
            urls = try_get_owned_bands_from_cookies_file(config.cookies_file)
            if urls is None:
                print("[bold red]Could not load cookies.txt file![/]")
            else:
                save_config(config)

    if len(urls) == 0:
        print(
            "[bold red]No bands found! Make sure you are logged in to bandcamp in some browser, or if you are using a cookies.txt file that it is still valid![/]"
        )
        return

    artist_url = inquirer.select(
        message="Choose an artist to upload to:", choices=list(urls)
    ).execute()

    session = requests.Session()
    session.mount("https://", BandcampHTTPAdapter())
    session.cookies = urls[artist_url]

    while True:
        album_path = inquirer.filepath(
            message="Enter path to album to upload (drag and drop folder here)",
            validate=dir_path_validator,
            filter=path_filter,
            invalid_message="Path must be to an existing directory",
        ).execute()

        album = Album.from_directory(album_path, config)
        album.upload(session, artist_url)

        proceed = inquirer.confirm("Upload another album?").execute()
        if not proceed:
            sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        logger.exception(ex)
    finally:
        input("Press enter to close...")
