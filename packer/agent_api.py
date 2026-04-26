"""
Nephele Workshop - Delivery Packer Agent API
Developer: ArisFusion Studio

Headless API layer for the Agent system.
Wraps logic.py packing features, returns standardized dicts.
"""

import logging
from pathlib import Path
from typing import Optional

from core._utils import api_ok, api_err
from .logic import DeliveryPacker, WatermarkMode, PackerError, create_text_watermark

logger = logging.getLogger(__name__)


def pack_image(
    input_path: str,
    watermark_path: Optional[str] = None,
    output_dir: Optional[str] = None,
    watermark_mode: str = "center",
    watermark_opacity: float = 0.3,
    preview_max_size: int = 1920,
    thumbnail_max_size: int = 500,
    protection_level: str = "none",
    copyright_info: str = "© ArisFusion Studio",
    output_folder_name: str = "Delivery_Pack",
) -> dict:
    """One-click image packing: HD + preview + thumbnail."""
    try:
        src = Path(input_path)
        if not src.exists():
            return api_err(f"文件不存在: {input_path}")

        mode_map = {"center": WatermarkMode.CENTER, "tile": WatermarkMode.TILE}
        wm_mode = mode_map.get(watermark_mode, WatermarkMode.CENTER)

        wm_path = Path(watermark_path) if watermark_path else None
        if wm_path and not wm_path.exists():
            return api_err(f"水印文件不存在: {watermark_path}")

        out_dir = Path(output_dir) if output_dir else None

        packer = DeliveryPacker(
            preview_max_size=preview_max_size,
            thumbnail_max_size=thumbnail_max_size,
            watermark_opacity=watermark_opacity,
            protection_level=protection_level,
            copyright_info=copyright_info,
            output_folder_name=output_folder_name,
        )

        result_dir, results = packer.process_image(
            input_path=src,
            watermark_path=wm_path,
            output_dir=out_dir,
            watermark_mode=wm_mode,
        )

        file_info = {k: str(v) for k, v in results.items()}
        return api_ok(
            f"打包完成，共生成 {len(results)} 个文件",
            output_path=str(result_dir),
            data={"files": file_info},
        )

    except PackerError as e:
        logger.error("打包失败: %s", e)
        return api_err(str(e))
    except Exception as e:
        logger.exception("打包时发生意外错误")
        return api_err(f"意外错误: {e}")


def generate_preview(
    input_path: str,
    output_path: str,
    watermark_path: Optional[str] = None,
    watermark_mode: str = "center",
    watermark_opacity: float = 0.3,
    max_size: int = 1920,
    protection_level: str = "none",
    copyright_info: str = "© ArisFusion Studio",
) -> dict:
    """Generate preview image only (with optional watermark + AI protection)."""
    try:
        src = Path(input_path)
        dst = Path(output_path)

        mode_map = {"center": WatermarkMode.CENTER, "tile": WatermarkMode.TILE}
        wm_mode = mode_map.get(watermark_mode, WatermarkMode.CENTER)
        wm_path = Path(watermark_path) if watermark_path else None

        packer = DeliveryPacker(
            preview_max_size=max_size,
            watermark_opacity=watermark_opacity,
            protection_level=protection_level,
            copyright_info=copyright_info,
        )

        image = packer.load_image(src)
        saved = packer.save_preview_version(image, dst, wm_path, wm_mode)

        return api_ok(
            "预览版生成完成",
            output_path=str(saved),
            data={"width": image.size[0], "height": image.size[1]},
        )

    except PackerError as e:
        logger.error("生成预览版失败: %s", e)
        return api_err(str(e))
    except Exception as e:
        logger.exception("生成预览版时发生意外错误")
        return api_err(f"意外错误: {e}")


def generate_thumbnail(
    input_path: str,
    output_path: str,
    max_size: int = 500,
) -> dict:
    """Generate thumbnail only."""
    try:
        src = Path(input_path)
        dst = Path(output_path)

        packer = DeliveryPacker(thumbnail_max_size=max_size)
        image = packer.load_image(src)
        saved = packer.save_thumbnail(image, dst)

        return api_ok(
            "缩略图生成完成",
            output_path=str(saved),
            data={"width": image.size[0], "height": image.size[1]},
        )

    except PackerError as e:
        logger.error("生成缩略图失败: %s", e)
        return api_err(str(e))
    except Exception as e:
        logger.exception("生成缩略图时发生意外错误")
        return api_err(f"意外错误: {e}")


def make_text_watermark(
    text: str,
    output_path: str,
    font_size: int = 72,
    color: tuple[int, int, int] = (255, 255, 255),
) -> dict:
    """Create a text watermark image."""
    try:
        dst = Path(output_path)
        saved = create_text_watermark(text, font_size, color, dst)
        return api_ok(f"文字水印已创建: {text}", output_path=str(saved))

    except PackerError as e:
        logger.error("创建文字水印失败: %s", e)
        return api_err(str(e))
    except Exception as e:
        logger.exception("创建文字水印时发生意外错误")
        return api_err(f"意外错误: {e}")
