import html
import http.cookiejar
import json
import logging
import re
import traceback
from pathlib import Path

import requests
from browser_cookie3 import (BrowserCookieError, brave, chrome, chromium, edge,
                             firefox, opera, opera_gx, safari, vivaldi)
from InquirerPy import inquirer
from rich import print

from config import init_config, load_config, save_config
from upload import Album

logger = logging.getLogger(__name__)

PAGEDATA_BLOB_REGEX = re.compile(r'<div id="pagedata" data-blob="(?P<data>[^"]*)"></div>')
def get_owned_bands(cj: http.cookiejar.CookieJar):
    r = requests.get("https://bandcamp.com", cookies=cj)
    data = PAGEDATA_BLOB_REGEX.search(r.text).group("data")
    data = json.loads(html.unescape(data))
    return [band["trackpipe_url_https"] for band in data["identities"]["bands"]]

def get_cj_from_cookie_fn(cookie_fn):
    cj = http.cookiejar.CookieJar()
    for cookie in cookie_fn(domain_name="bandcamp.com"):
        cj.set_cookie(cookie)
    return cj

def get_owned_bandcamp_artist_urls():
    url_to_cj = {}
    for cookie_fn in [brave, chrome, chromium, edge, firefox, opera, opera_gx, safari, vivaldi]:
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
                url_to_cj[url] = cookie_fn
        except BrowserCookieError:
            pass
    return url_to_cj

def main():
    config = load_config()
    if config is None:
        print("No config file detected. Launching first time setup...")
        config = init_config()
        save_config(config)
        print("Config saved!")
    urls_and_cjs = get_owned_bandcamp_artist_urls()
    artist_url = inquirer.select(
        message="Choose an artist to upload to:",
        choices=list(urls_and_cjs)
    ).execute()
    
    def album_path_filter(path: str):
        return Path(path.strip("\"'& "))
    
    def album_path_validator(path: str):
        path = album_path_filter(path)
        return path.exists() and path.is_dir()
    
    album_path = inquirer.filepath(
        message="Enter path to album to upload (drag and drop folder here)",
        validate=album_path_validator,
        filter=album_path_filter,
        invalid_message="Path must be to an existing directory"
    ).execute()
    
    session = requests.Session()
    session.cookies = get_cj_from_cookie_fn(urls_and_cjs[artist_url])

    album = Album.from_directory(album_path, config)
    album.upload(session, artist_url)

if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        logger.exception(ex)
    finally:
        input("Press enter to close...")