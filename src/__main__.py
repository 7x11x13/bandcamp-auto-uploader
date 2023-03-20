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

def load_cj_from_cookies_txt(cookies_file: str):
    cj = http.cookiejar.MozillaCookieJar(cookies_file)
    cj.load()
    return cj

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
    
    def path_filter(path: str) -> Path:
        return Path(path.strip("\"'& "))
    
    def dir_path_validator(path: str):
        path = path_filter(path)
        return path.exists() and path.is_dir()
    
    def file_path_validator(path: str):
        path = path_filter(path)
        return path.exists() and not path.is_dir()
    
    config = load_config()
    if config is None:
        print("No config file detected. Launching first time setup...")
        config = init_config()
        save_config(config)
        print("Config saved!")
    cookies_loaded = False
    if config.cookies_file:
        print(f"Loading cookies from {config.cookies_file}")
        try:
            cj = load_cj_from_cookies_txt(config.cookies_file)
            urls = get_owned_bands(cj)
            cookies_loaded = True
        except Exception as ex:
            logger.exception(ex)
            print("Could not load cookies.txt file, trying to automatically get cookies")
    if not cookies_loaded:
        try:
            urls = get_owned_bandcamp_artist_urls()
        except Exception as ex:
            logger.exception(ex)
            print("Could not automatically get cookies")
            cookies_path = inquirer.filepath(
                message="Enter path to bandcamp cookies.txt file (or drag and drop file here)",
                validate=file_path_validator,
                filter=path_filter,
                invalid_message="Path must be to an existing file"
            ).execute()
            config.cookies_file = cookies_path
            save_config(config)
            
    if len(urls) == 0:
        print("No bands found! Make sure you are logged in to bandcamp in some browser, or if you are using a cookies.txt file that it is still valid!")
        return
        
    artist_url = inquirer.select(
            message="Choose an artist to upload to:",
            choices=list(urls)
        ).execute()
    album_path = inquirer.filepath(
        message="Enter path to album to upload (drag and drop folder here)",
        validate=dir_path_validator,
        filter=path_filter,
        invalid_message="Path must be to an existing directory"
    ).execute()
    
    session = requests.Session()
    if config.cookies_file:
        session.cookies = cj
    else:
        session.cookies = get_cj_from_cookie_fn(urls[artist_url])

    album = Album.from_directory(album_path, config)
    album.upload(session, artist_url)

if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        logger.exception(ex)
    finally:
        input("Press enter to close...")