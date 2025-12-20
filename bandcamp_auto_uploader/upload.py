import dataclasses
import html
from io import BufferedReader
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

import mutagen
import requests
from mutagen.aiff import AIFF
from mutagen.flac import FLAC
from mutagen.wave import WAVE
from rich.logging import RichHandler

from bandcamp_auto_uploader.config import Config

logger = logging.getLogger("bandcamp-auto-uploader")
logger.setLevel(logging.INFO)
logger.addHandler(RichHandler())


@dataclasses.dataclass
class BandcampAlbumData:
    id: str = ""
    title: str = ""
    release_date: str = ""
    price: str = "0.00"
    nyp: int = 1
    label_id: int = 0
    new_desc_format: int = 1
    download_desc: str = ""
    art_id: str = ""
    artist: str = ""
    about: str = ""
    credits: str = ""
    tags: str = ""
    upc: str = ""
    cat_number: str = ""
    public: int = 1
    tralbum_release_message: str = ""
    subscriber_only_message: str = ""

    def to_dict(self) -> dict:
        d = {}
        for k, v in dataclasses.asdict(self).items():
            k = f"album.{k}"
            d[k] = v
        return d


@dataclasses.dataclass
class BandcampTrackData:
    id: str = ""
    track_number: int = 1
    action: str = "edit"
    featured: int = 0
    title: str = "track 1"
    streaming: int = 1
    enable_download: int = 1
    price: str = "0.00"
    nyp: int = 1
    label_id: int = 0
    new_desc_format: int = 1
    download_desc: str = ""
    about: str = ""
    lyrics: str = ""
    credits: str = ""
    video_id: str = ""
    video_filename: str = ""
    video_delete: str = ""
    video_caption: str = ""
    artist: str = ""
    art_id: str = ""
    tags: str = ""
    license_type: str = "1"
    isrc: str = ""
    release_date: str = ""
    encodings_id: str = ""

    def to_dict(self, track_number: int) -> dict:
        d = {}
        for k, v in dataclasses.asdict(self).items():
            if k.startswith("video"):
                k = k.replace("_", "-")
            k = f"track.{k}_{track_number}"
            d[k] = v
        return d


def post_request_with_crumb(session: requests.Session, url: str, data: dict) -> Any:
    r = session.post(url, data=data)
    logger.debug(r.text)
    r.raise_for_status()
    res = r.json()
    if res.get("error") == "invalid_crumb":
        data["crumb"] = res["crumb"]
        r = session.post(url, data=data)
        logger.debug(r.text)
        r.raise_for_status()
        res = r.json()
    return res


UPLOADED_FILE_KEY_REGEX = re.compile(r"<Key>(?P<key>[^<]*)</Key>")


def upload_file(
    session: requests.Session,
    artist_url: str,
    file_name: str,
    crumbs: dict,
    api_path: str,
    file_path: Optional[Path] = None,
    file_data: Optional[bytes] = None,
):
    file_name = file_name.encode().decode("ascii", errors="replace")
    logger.info(f"Uploading file '{file_name}'...")
    # get upload params
    upload_params_url = urljoin(artist_url, "api/gcsupload_info/1/get_upload_params")
    r = session.post(upload_params_url, json={"filename": file_name})
    logger.debug(r.text)
    r.raise_for_status()
    data = r.json()
    logger.debug(f"Params: {data}")
    gcs_url = data["url"]
    params = {param["key"]: param["value"] for param in data["params"]}

    # upload file
    start_time = time.time()
    multipart_form_data: dict[str, tuple[str | None, bytes | BufferedReader]] = {
        k: (None, v) for k, v in params.items()
    }
    if file_data is not None:
        multipart_form_data["file"] = (file_name, file_data)
        r = session.post(gcs_url, files=multipart_form_data)
        r.raise_for_status()
    elif file_path is not None:
        with open(file_path, "rb") as f:
            multipart_form_data["file"] = (file_name, f)
            r = session.post(gcs_url, files=multipart_form_data)
            logger.debug(f"Response: {r.text}")
            r.raise_for_status()
    else:
        raise ValueError("Either file_path or file_data must be specified")
    duration = time.time() - start_time
    logger.debug(f"Uploaded: {r.text}")

    m = UPLOADED_FILE_KEY_REGEX.search(r.text)
    if m is None:
        raise ValueError("Could not find uploaded file key")
    uploaded_file_key = m.group("key")
    uploaded_file_key = html.unescape(uploaded_file_key)

    # tell api we uploaded file
    uploaded_file_data = {
        "type": "gcs",
        "filename": file_name,
        "key": uploaded_file_key,
        "duration": int(duration * 1000),
        "crumb": crumbs[api_path],
    }
    uploaded_track_url = urljoin(artist_url, api_path)
    r = post_request_with_crumb(session, uploaded_track_url, uploaded_file_data)
    logger.info(f"File uploaded in {duration:.2f} seconds!")
    logger.debug(f"{r}")
    return r


def generate_cover_file_name_from_mimetype(mime: str):
    return "cover." + mime.split("/")[-1]


class CoverArt:
    def __init__(
        self,
        path: Optional[Path] = None,
        data: Optional[bytes] = None,
        file_name: Optional[str] = None,
    ):
        self.path = path
        self.data = data

        if path is not None:
            self.file_name = path.name
        else:
            assert file_name is not None
            self.file_name = file_name

        if path is None and (data is None or file_name is None):
            raise ValueError(
                "Either file path or data and name must be initialized for cover art"
            )

    def upload(self, session: requests.Session, artist_url: str, crumbs: dict) -> str:
        if self.path is not None:
            r = upload_file(
                session,
                artist_url,
                self.file_name,
                crumbs,
                "tralbum_art_uploaded",
                file_path=self.path,
            )
        else:
            r = upload_file(
                session,
                artist_url,
                self.file_name,
                crumbs,
                "tralbum_art_uploaded",
                file_data=self.data,
            )
        if r.get("error"):
            raise ValueError(r.get("deets"))
        return r["art_id"]


class Track:
    def __init__(
        self,
        path: Path,
        track_data: BandcampTrackData,
        cover_art: Optional[CoverArt] = None,
    ):
        self.path = path
        self.file_name = self.path.name
        self.track_data = track_data
        self.cover_art = cover_art

    @classmethod
    def from_file(cls, path: Path, config: Config):
        path = Path(path)
        track_data = BandcampTrackData(
            price=str(config.track_price),
            nyp=int(config.name_your_price),
            enable_download=int(config.track_downloading),
            streaming=int(config.track_streaming),
        )
        file_data = mutagen.File(path)
        if file_data is None:
            return None
        if file_data.__class__ not in (WAVE, FLAC, AIFF):
            raise ValueError("Bandcamp only accepts wav, flac, or aiff files")
        cover_art = None
        if file_data.__class__ == FLAC:
            # flac tags
            if "title" in file_data:
                track_data.title = file_data["title"]
            else:
                track_data.title = path.name
            if "artist" in file_data:
                track_data.artist = file_data["artist"][0]
            if "tracknumber" in file_data:
                track_data.track_number = file_data["tracknumber"][0]
            if "comment" in file_data:
                track_data.about = file_data["comment"][0]
            if "genre" in file_data:
                track_data.tags = ",".join(file_data["genre"])
            if "isrc" in file_data:
                track_data.isrc = file_data["isrc"][0]
            # cover art
            if config.upload_track_art and len(file_data.pictures) > 0:
                name = generate_cover_file_name_from_mimetype(
                    file_data.pictures[0].mime
                )
                cover_art = CoverArt(data=file_data.pictures[0].data, file_name=name)
        else:
            # id3 tags
            if "TIT2" in file_data:
                track_data.title = file_data["TIT2"].text[0]
            else:
                track_data.title = path.name
            if "TPE1" in file_data:
                track_data.artist = file_data["TPE1"].text[0]
            if "TRCK" in file_data:
                track_data.track_number = file_data["TRCK"].text[0]
            if "TCON" in file_data:
                track_data.tags = ",".join(file_data["TCON"].text)
            if "TSRC" in file_data:
                track_data.isrc = file_data["TSRC"].text[0]
            if "USLT" in file_data:
                track_data.lyrics = file_data["USLT"].text[0]
            if file_data.tags is not None:
                comments = file_data.tags.getall("COMM")
                if len(comments) > 0:
                    track_data.about = comments[0].text[0]
                # cover art
                pictures = file_data.tags.getall("APIC")
                if config.upload_track_art and len(pictures) > 0:
                    name = generate_cover_file_name_from_mimetype(pictures[0].mime)
                    cover_art = CoverArt(data=pictures[0].data, file_name=name)
        # convert track number to int
        if not isinstance(track_data.track_number, int):
            try:
                track_data.track_number = int(track_data.track_number.split("/")[0])
            except ValueError:
                track_data.track_number = 0
        return cls(path, track_data, cover_art)

    def upload(self, session: requests.Session, artist_url: str, crumbs: dict):
        r = upload_file(
            session,
            artist_url,
            self.file_name,
            crumbs,
            "uploaded_track",
            file_path=self.path,
        )
        self.track_data.encodings_id = r["encodings"]["id"]

        # upload cover art
        if self.cover_art is not None:
            cover_art_id = self.cover_art.upload(session, artist_url, crumbs)
            self.track_data.art_id = cover_art_id


class Album:
    CRUMB_DATA_REGEX = re.compile(
        r'<meta id="js-crumbs-data" data-crumbs="(?P<crumbs>[^>]*)">'
    )

    def __init__(
        self,
        album_data: BandcampAlbumData,
        tracks: list[Track],
        cover_art: Optional[CoverArt] = None,
    ):
        self.album_data = album_data
        self.tracks = tracks
        self.cover_art = cover_art

    @classmethod
    def from_directory(cls, path: Path, config: Config):
        path = Path(path)
        if not path.is_dir():
            raise ValueError("Album to upload must be a directory")
        album_data = BandcampAlbumData(
            title=path.name,
            price=str(config.album_price),
            nyp=int(config.name_your_price),
        )
        tracks = []
        for file in path.iterdir():
            track = Track.from_file(file, config)
            if track is not None:
                tracks.append(track)
        tracks.sort(
            key=lambda track: (track.track_data.track_number, track.track_data.title)
        )
        cover_art = None
        for file in path.iterdir():
            s = str(file).lower()
            if s[-4:] in (".jpg", ".png", ".gif") or s[-5:] == ".jpeg":
                cover_art = CoverArt(path=file)
                break
        return cls(album_data, tracks, cover_art)

    def upload(self, session: requests.Session, artist_url: str):
        logger.info("Starting album upload")
        logger.info("Getting crumbs...")
        create_album_url = urljoin(artist_url, "edit_album")
        r = session.get(create_album_url)
        logger.debug(r.text)
        r.raise_for_status()
        m = self.CRUMB_DATA_REGEX.search(r.text)
        if m is None:
            raise ValueError("Could not find crumbs")
        crumbs = m.group("crumbs")
        crumbs = json.loads(html.unescape(crumbs))
        logger.info("Got crumbs!")
        logger.debug(f"Crumbs: {crumbs}")

        # upload cover art
        if self.cover_art is not None:
            logger.info("Uploading cover art...")
            cover_art_id = self.cover_art.upload(session, artist_url, crumbs)
            self.album_data.art_id = cover_art_id

        # save changes to album
        bandcamp_data = {
            "paypal_aware": "",
            "action": "save",
            "publish_campaign": "false",
            "crumb": crumbs["edit_album_cb"],
        }
        bandcamp_data.update(self.album_data.to_dict())
        edit_album_cb_url = urljoin(artist_url, "edit_album_cb")
        logger.info("Saving changes to album...")
        r = post_request_with_crumb(session, edit_album_cb_url, bandcamp_data)
        logger.info(f"Saved changes to album! ID = {r['album']['id']}")
        bandcamp_data["album.id"] = r["album"]["id"]

        for i, track in enumerate(self.tracks):
            logger.info(f"Uploading track {i + 1}/{len(self.tracks)}...")
            track.upload(session, artist_url, crumbs)
            logger.info("Track uploaded!")
            bandcamp_data.update(track.track_data.to_dict(i))
            logger.info("Saving changes to album...")
            r = post_request_with_crumb(session, edit_album_cb_url, bandcamp_data)
            logger.info(f"Saved changes to album! Last track ID = {r['track_ids'][-1]}")
            bandcamp_data[f"track.id_{i}"] = r["track_ids"][-1]
        logger.info("Upload complete!")
