import dataclasses
import json
from pathlib import Path

import appdirs
from InquirerPy import inquirer


@dataclasses.dataclass
class Config:
    album_price: float = 0
    track_price: float = 0
    name_your_price: bool = True
    track_streaming: bool = True
    track_downloading: bool = True
    upload_track_art: bool = True
    cookies_file: str = ""
    debug: bool = False


config_file = Path(
    appdirs.user_config_dir("bandcamp-auto-uploader", "7x11x13"), "config.json"
)


def get_config_file_path() -> Path:
    return config_file


def load_config():
    if not config_file.exists():
        return None
    with open(config_file, "r") as f:
        config = Config(**json.load(f))
        return config


def save_config(config: Config):
    config_file.parent.mkdir(parents=True, exist_ok=True)
    with open(config_file, "w") as f:
        json.dump(dataclasses.asdict(config), f, indent=4)


def init_config():
    def price_validator(price):
        try:
            price = float(price)
            if price >= 0:
                return True
        except Exception:
            return False

    config = Config()
    config.album_price = inquirer.text(
        message="Default album price:",
        filter=lambda price: round(float(price), 2),
        validate=price_validator,
        invalid_message="Price must be a number >= 0",
    ).execute()
    config.track_price = inquirer.text(
        message="Default track price:",
        filter=lambda price: round(float(price), 2),
        validate=price_validator,
        invalid_message="Price must be a number >= 0",
    ).execute()
    config.name_your_price = inquirer.select(
        message="Default name-your-price?",
        filter=lambda choice: choice == "Yes",
        choices=["Yes", "No"],
    ).execute()
    config.track_streaming = inquirer.select(
        message="Default allow streaming?",
        filter=lambda choice: choice == "Yes",
        choices=["Yes", "No"],
    ).execute()
    config.track_downloading = inquirer.select(
        message="Default allow track downloading?",
        filter=lambda choice: choice == "Yes",
        choices=["Yes", "No"],
    ).execute()
    config.upload_track_art = inquirer.select(
        message="Upload individual track art (not the album art) if it exists?",
        filter=lambda choice: choice == "Yes",
        choices=["Yes", "No"],
    ).execute()
    return config
