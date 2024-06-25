import html
import http.cookiejar
import json
import logging
import re
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

from .config import get_config_file_path, init_config, load_config, save_config
from .upload import Album

__version__ = "v0.2.3"

logger = logging.getLogger("bandcamp-auto-uploader")

PAGEDATA_BLOB_REGEX = re.compile(
    r'<div id="pagedata" data-blob="(?P<data>[^"]*)"></div>'
)


def get_owned_bands(cj: http.cookiejar.CookieJar):
    r = requests.get("https://bandcamp.com", cookies=cj)
    data = PAGEDATA_BLOB_REGEX.search(r.text).group("data")
    data = json.loads(html.unescape(data))
    return [band["trackpipe_url_https"] for band in data["identities"]["bands"]]


def try_get_owned_bands_from_cookies_file(
    cookies_file: str,
) -> Optional[dict[str, http.cookiejar.CookieJar]]:
    print(f"[yellow]Loading cookies from {escape(cookies_file)}[/]")
    try:
        cj = http.cookiejar.MozillaCookieJar(cookies_file)
        cj.load()
        return {url: cj for url in get_owned_bands(cj)}
    except Exception as ex:
        logger.exception(ex)
        return None


def try_get_owned_bands_from_browsers() -> (
    Optional[dict[str, http.cookiejar.CookieJar]]
):
    print(f"[yellow]Loading cookies from browsers[/]")
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
                    url_to_cj[url] = cj
            except BrowserCookieError:
                pass
        return url_to_cj
    except Exception as ex:
        logger.exception(ex)
        print("[bold red]Could not automatically get cookies[/]")
        return None


def main():

    def path_filter(path: str) -> Path:
        return Path(path.strip("\"'& "))

    def dir_path_validator(path: str):
        path = path_filter(path)
        return path.exists() and path.is_dir()

    def file_path_validator(path: str):
        path = path_filter(path)
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
    album_path = inquirer.filepath(
        message="Enter path to album to upload (drag and drop folder here)",
        validate=dir_path_validator,
        filter=path_filter,
        invalid_message="Path must be to an existing directory",
    ).execute()

    session = requests.Session()
    session.cookies = urls[artist_url]

    album = Album.from_directory(album_path, config)
    album.upload(session, artist_url)


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        logger.exception(ex)
    finally:
        input("Press enter to close...")
