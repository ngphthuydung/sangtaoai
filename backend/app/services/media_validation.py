"""Validation for supported inline media uploads."""

from io import BytesIO
import wave

from PIL import Image, UnidentifiedImageError

MAX_IMAGE_PIXELS = 20_000_000
IMAGE_FORMATS = {
    "image/jpeg": "JPEG",
    "image/png": "PNG",
    "image/webp": "WEBP",
}
MP4_AUDIO_BRANDS = {b"M4A ", b"M4B ", b"M4P ", b"isom", b"iso2", b"mp41", b"mp42"}


class InvalidMediaError(ValueError):
    """Raised when a media body is corrupt or mismatches its declared type."""


def validate_image(image: bytes, mime_type: str) -> tuple[int, int]:
    expected_format = IMAGE_FORMATS.get(mime_type)
    if expected_format is None:
        raise InvalidMediaError("Unsupported image MIME type")
    try:
        with Image.open(BytesIO(image)) as decoded:
            if decoded.format != expected_format:
                raise InvalidMediaError("Image format does not match Content-Type")
            width, height = decoded.size
            if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS:
                raise InvalidMediaError("Image dimensions exceed the supported limit")
            decoded.load()
    except InvalidMediaError:
        raise
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as error:
        raise InvalidMediaError("Image data is invalid or incomplete") from error
    return width, height


def _is_mpeg_audio_frame(data: bytes, offset: int) -> bool:
    if offset + 4 > len(data):
        return False
    header = int.from_bytes(data[offset : offset + 4], "big")
    return (
        header >> 21 == 0x7FF
        and ((header >> 19) & 0b11) != 0b01
        and ((header >> 17) & 0b11) != 0
        and ((header >> 12) & 0b1111) not in {0, 15}
        and ((header >> 10) & 0b11) != 0b11
    )


def _has_mp3_signature(audio: bytes) -> bool:
    if audio.startswith(b"ID3"):
        if len(audio) < 10:
            return False
        version = audio[3]
        flags = audio[5]
        tag_size_bytes = audio[6:10]
        if (
            version in {0xFF, 0}
            or any(byte & 0x80 for byte in tag_size_bytes)
            or flags & 0x0F
        ):
            return False
        tag_size = (
            (tag_size_bytes[0] << 21)
            | (tag_size_bytes[1] << 14)
            | (tag_size_bytes[2] << 7)
            | tag_size_bytes[3]
        )
        frame_offset = 10 + tag_size + (10 if flags & 0x10 else 0)
        return _is_mpeg_audio_frame(audio, frame_offset)
    return any(_is_mpeg_audio_frame(audio, offset) for offset in range(min(len(audio), 4096)))


def _has_wav_signature(audio: bytes) -> bool:
    try:
        with wave.open(BytesIO(audio), "rb") as source:
            return (
                source.getnchannels() > 0
                and source.getframerate() > 0
                and source.getnframes() > 0
                and source.getcomptype() == "NONE"
            )
    except (EOFError, wave.Error):
        return False


def has_audio_signature(audio: bytes, mime_type: str) -> bool:
    if mime_type == "audio/mpeg":
        return _has_mp3_signature(audio)
    if mime_type == "audio/wav":
        return _has_wav_signature(audio)
    if mime_type == "audio/mp4":
        return (
            len(audio) >= 16
            and audio[4:8] == b"ftyp"
            and audio[8:12] in MP4_AUDIO_BRANDS
        )
    return False
