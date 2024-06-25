# bandcamp-auto-uploader

Upload albums in bulk without a Bandcamp Pro account. Automatically set track artist/title/comments/art based on track metadata.
![Example](/docs/screenshot.png)

## Installation

### Binary
Download the latest release for your platform [here](https://github.com/7x11x13/bandcamp-auto-uploader/releases)

### PyPI
```
$ pip install bandcamp-auto-uploader
$ bc-upload
```

## Notes

- You must be signed in to the account you want to upload to in at least one browser (or you must supply a cookies.txt file)
- Supported browsers are found [here](https://github.com/borisbabic/browser_cookie3#contribute)
- RIFF tags are not currently supported by mutagen, so if you want your tracks to be named from the metadata make sure to use ID3 tags
- The program ignores any non-audio files in the album folder except for the first image it encounters which it makes the album cover
- Bandcamp only allows WAV, FLAC, and AIFF files to be uploaded

## Acknowledgements

- Thanks [SeyNoe](https://seynoe.bandcamp.com/) for testing
