"""
Nephele Workshop - Watermark Protection Module (local)

Embeds/extracts invisible blind watermarks using blind_watermark locally.
No network dependency — works offline.

Uses file-based I/O + bit mode for reliable embedding/extraction
(numpy array mode has known issues with blind_watermark library).

Public API unchanged:
    protect_image(image, level, copyright_info) -> Image
    extract_watermark(image) -> str | None
    save_with_watermark(image, output_path) -> bool

Developer: ArisFusion Studio
"""

import logging
import tempfile
from enum import Enum
from pathlib import Path
from typing import Optional

import numpy as np
from PIL import Image

logger = logging.getLogger(__name__)

# Watermark payload: fixed 32 bytes (256 bits)
# Enough for 10 Chinese chars (UTF-8, 3 bytes each) or 32 ASCII chars
WATERMARK_BYTES = 32
WATERMARK_BITS = WATERMARK_BYTES * 8
_WM_PASSWORD_IMG = 2024
_WM_PASSWORD_WM = 1314


class ProtectionLevel(Enum):
    NONE = "none"
    INVISIBLE = "invisible"


LEVEL_ALIASES = {"maximum": "invisible"}


def _text_to_bits(text: str) -> list[int]:
    """Convert text to fixed-length bit array via UTF-8."""
    raw = text.encode("utf-8")[:WATERMARK_BYTES]
    padded = raw.ljust(WATERMARK_BYTES, b"\x00")
    bits = []
    for byte in padded:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_text(bits: list) -> str:
    """Convert bit array back to text via UTF-8."""
    raw = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i+8]
        if len(chunk) < 8:
            break
        val = 0
        for b in chunk:
            val = (val << 1) | (1 if b > 0.5 else 0)
        raw.append(val)
    return raw.rstrip(b"\x00").decode("utf-8", errors="replace")


class WatermarkEngine:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def embed(self, image: Image.Image, text: str) -> Image.Image:
        """Embed invisible watermark using file-based blind_watermark."""
        try:
            from blind_watermark import WaterMark

            rgb = image.convert("RGB")
            alpha = image.split()[3] if image.mode == "RGBA" else None

            with tempfile.TemporaryDirectory() as tmpdir:
                orig_path = str(Path(tmpdir) / "orig.png")
                wm_path = str(Path(tmpdir) / "watermarked.png")

                rgb.save(orig_path, format="PNG")

                bits = _text_to_bits(text)

                bwm = WaterMark(password_img=_WM_PASSWORD_IMG, password_wm=_WM_PASSWORD_WM)
                bwm.read_img(orig_path)
                bwm.read_wm(np.array(bits), mode="bit")
                bwm.embed(wm_path)

                result_img = Image.open(wm_path).convert("RGB")

                # Verify extraction round-trip
                extracted_bits = WaterMark(
                    password_img=_WM_PASSWORD_IMG, password_wm=_WM_PASSWORD_WM
                ).extract(wm_path, wm_shape=WATERMARK_BITS, mode="bit")
                extracted_text = _bits_to_text(extracted_bits)

                if extracted_text == text[:WATERMARK_BYTES]:
                    logger.info("[Watermark] Verified: '%s'", extracted_text)
                else:
                    logger.warning("[Watermark] Verify mismatch: '%s' -> '%s'",
                                   text[:WATERMARK_BYTES], extracted_text)

            if alpha:
                result_img = result_img.convert("RGBA")
                result_img.putalpha(alpha)

            return result_img

        except Exception as e:
            logger.error("Embed failed: %s", e, exc_info=True)
            return image

    def extract(self, image: Image.Image) -> Optional[str]:
        """Extract invisible watermark using file-based blind_watermark."""
        try:
            from blind_watermark import WaterMark

            rgb = image.convert("RGB")
            bit_len = WATERMARK_BITS

            with tempfile.TemporaryDirectory() as tmpdir:
                img_path = str(Path(tmpdir) / "check.png")
                rgb.save(img_path, format="PNG")

                extracted_bits = WaterMark(
                    password_img=_WM_PASSWORD_IMG, password_wm=_WM_PASSWORD_WM
                ).extract(img_path, wm_shape=bit_len, mode="bit")

            text = _bits_to_text(extracted_bits)
            return text.strip() if text.strip() else None
        except Exception as e:
            logger.warning("Extract failed: %s", e)
            return None


def protect_image(
    image: Image.Image,
    level: str = "none",
    copyright_info: str = "ARIS"
) -> Image.Image:
    level = LEVEL_ALIASES.get(level, level)
    if level == "invisible":
        return WatermarkEngine().embed(image, copyright_info)
    return image


def extract_watermark(image: Image.Image) -> Optional[str]:
    return WatermarkEngine().extract(image)


def save_with_watermark(image: Image.Image, output_path: str) -> bool:
    try:
        image.save(output_path, format='PNG')
        return True
    except Exception as e:
        logger.warning("Save failed: %s", e)
        return False
