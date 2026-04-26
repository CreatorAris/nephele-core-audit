"""
Nephele Workshop - Delivery Packer Logic
Developer: ArisFusion Studio

核心功能：图像加载、水印处理、多尺寸输出
"""

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple, Callable

from PIL import Image, ImageDraw, ImageFont
from .watermark_protection import protect_image, save_with_watermark


class WatermarkMode(Enum):
    """水印模式枚举"""
    CENTER = "center"  # 居中大水印
    TILE = "tile"      # 全屏平铺水印


class PackerError(Exception):
    """打包器自定义异常"""
    pass


class DeliveryPacker:
    """
    交付文件打包器
    
    功能：
    - 加载多种格式图片（PNG/JPG/PSD）
    - 生成高清版（无损PNG）
    - 生成预览版（带水印，尺寸调整）
    - 生成缩略图
    - 统一输出管理
    """
    
    # 默认配置
    DEFAULT_PREVIEW_MAX_SIZE = 1920
    DEFAULT_THUMBNAIL_MAX_SIZE = 500
    DEFAULT_WATERMARK_OPACITY = 0.3  # 水印透明度 (0.0-1.0)
    
    def __init__(
        self,
        preview_max_size: int = DEFAULT_PREVIEW_MAX_SIZE,
        thumbnail_max_size: int = DEFAULT_THUMBNAIL_MAX_SIZE,
        watermark_opacity: float = DEFAULT_WATERMARK_OPACITY,
        protection_level: str = "none",
        copyright_info: str = "© ArisFusion Studio",
        text_watermark_content: str = "",
        output_folder_name: str = "Delivery_Pack"
    ):
        """
        初始化打包器
        
        Args:
            preview_max_size: 预览版长边最大尺寸（像素）
            thumbnail_max_size: 缩略图长边最大尺寸（像素）
            watermark_opacity: 水印不透明度 (0.0-1.0)
            protection_level: AI保护级别 ("none", "invisible")
            copyright_info: 版权信息（用于隐形水印）
            text_watermark_content: 文字水印内容
            output_folder_name: 输出文件夹名称
        """
        self.preview_max_size = preview_max_size
        self.thumbnail_max_size = thumbnail_max_size
        self.watermark_opacity = max(0.0, min(1.0, watermark_opacity))
        self.protection_level = protection_level
        self.copyright_info = copyright_info
        self.text_watermark_content = text_watermark_content
        self.output_folder_name = output_folder_name
        
    def load_image(self, file_path: Path) -> Image.Image:
        """
        加载图片（支持 PNG/JPG/PSD）
        
        Args:
            file_path: 图片文件路径
            
        Returns:
            PIL Image 对象
            
        Raises:
            PackerError: 文件不存在或格式不支持时抛出
        """
        if not file_path.exists():
            raise PackerError(f"文件不存在: {file_path}")
        
        suffix = file_path.suffix.lower()
        
        try:
            # 处理标准图片格式
            if suffix in ['.png', '.jpg', '.jpeg', '.webp', '.bmp']:
                img = Image.open(file_path)
                # PNG/WEBP保持透明度，JPG转为RGB
                if suffix in ['.png', '.webp'] and img.mode in ('RGBA', 'LA', 'PA'):
                    # 已有alpha通道，保持
                    return img
                elif suffix in ['.png', '.webp']:
                    # PNG/WEBP但无alpha，转为RGBA以支持后续透明水印
                    return img.convert('RGBA')
                else:
                    # JPG/BMP不支持透明，转为RGB
                    if img.mode != 'RGB':
                        img = img.convert('RGB')
                    return img
            
            # 处理 PSD 文件
            elif suffix in ['.psd', '.psb']:
                try:
                    from psd_tools import PSDImage
                    psd = PSDImage.open(file_path)
                    # 合并所有可见图层并转换为 PIL Image
                    img = psd.composite()
                    if img.mode != 'RGBA':
                        img = img.convert('RGBA')
                    return img
                except ImportError:
                    raise PackerError(
                        "PSD 文件需要 psd-tools 库支持\n"
                        "请运行: pip install psd-tools"
                    )
            else:
                raise PackerError(
                    f"不支持的文件格式: {suffix}\n"
                    f"支持的格式: .PNG, .JPG, .PSD"
                )
                
        except PackerError:
            raise
        except Exception as e:
            raise PackerError(f"加载图片失败: {str(e)}")
    
    def save_hd_version(
        self,
        image: Image.Image,
        output_path: Path
    ) -> Path:
        """
        保存高清版（无损 PNG）
        
        Args:
            image: PIL Image 对象
            output_path: 输出文件路径
            
        Returns:
            保存的文件路径
        """
        try:
            # 确保输出目录存在
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 使用水印安全保存（保留原始字节避免二次编码）
            save_with_watermark(image, str(output_path))
            return output_path
            
        except Exception as e:
            raise PackerError(f"保存高清版失败: {str(e)}")
    
    @staticmethod
    def crop_to_ratio(
        image: Image.Image,
        target_w: int,
        target_h: int,
    ) -> Image.Image:
        """
        中心裁切到目标宽高比。

        如果原图已经是目标比例（误差 < 0.01），直接返回副本。

        Args:
            image: 原始图片
            target_w: 目标宽度比例值（如 16）
            target_h: 目标高度比例值（如 9）

        Returns:
            裁切后的图片（新对象）
        """
        img_w, img_h = image.size
        target_ratio = target_w / target_h
        img_ratio = img_w / img_h

        # 已经是目标比例，无需裁切
        if abs(img_ratio - target_ratio) < 0.01:
            return image.copy()

        if img_ratio > target_ratio:
            # 图片更宽 → 裁左右
            new_w = int(img_h * target_ratio)
            left = (img_w - new_w) // 2
            return image.crop((left, 0, left + new_w, img_h))
        else:
            # 图片更高 → 裁上下
            new_h = int(img_w / target_ratio)
            top = (img_h - new_h) // 2
            return image.crop((0, top, img_w, top + new_h))

    def resize_image(
        self,
        image: Image.Image,
        max_size: int,
        resample: int = Image.LANCZOS
    ) -> Image.Image:
        """
        调整图片尺寸（保持宽高比，长边限制）
        
        Args:
            image: 原始图片
            max_size: 长边最大尺寸（像素）
            resample: 重采样算法
            
        Returns:
            调整后的图片
        """
        width, height = image.size
        
        # 如果图片已经小于目标尺寸，不放大
        if width <= max_size and height <= max_size:
            return image.copy()
        
        # 计算缩放比例（长边限制）
        if width > height:
            new_width = max_size
            new_height = int(height * (max_size / width))
        else:
            new_height = max_size
            new_width = int(width * (max_size / height))
        
        return image.resize((new_width, new_height), resample)
    
    def apply_watermark(
        self,
        image: Image.Image,
        watermark_path: Path,
        mode: WatermarkMode = WatermarkMode.CENTER,
        scale: float = 0.4,
        rotation: float = 0.0,
        tile_gap: int = 0,
        tile_stagger: bool = False
    ) -> Image.Image:
        """
        Apply watermark to image.

        Args:
            image: Base image
            watermark_path: Watermark image path
            mode: Watermark mode (center/tile)
            scale: Watermark scale relative to base image width (0.05-2.0)
            rotation: Rotation angle in degrees (0-360)
            tile_gap: Extra gap between tiles in pixels (0-500)
            tile_stagger: Offset odd rows by half for brick pattern

        Returns:
            Image with watermark applied
        """
        if not watermark_path.exists():
            raise PackerError(f"水印文件不存在: {watermark_path}")

        try:
            watermark = Image.open(watermark_path)
            if watermark.mode != 'RGBA':
                watermark = watermark.convert('RGBA')

            output = image.copy()

            if mode == WatermarkMode.CENTER:
                output = self._apply_center_watermark(output, watermark, scale, rotation)
            elif mode == WatermarkMode.TILE:
                output = self._apply_tile_watermark(output, watermark, scale, rotation, tile_gap, tile_stagger)

            return output

        except PackerError:
            raise
        except Exception as e:
            raise PackerError(f"应用水印失败: {str(e)}")
    
    def _apply_center_watermark(
        self,
        image: Image.Image,
        watermark: Image.Image,
        scale: float,
        rotation: float = 0.0
    ) -> Image.Image:
        """Apply single centered watermark with optional rotation."""
        img_width, img_height = image.size
        wm_width = int(img_width * scale)
        wm_height = int(watermark.size[1] * (wm_width / watermark.size[0]))

        watermark_resized = watermark.resize((wm_width, wm_height), Image.LANCZOS)
        watermark_with_opacity = self._adjust_opacity(watermark_resized, self.watermark_opacity)

        # Rotate if needed (expand=True to avoid clipping)
        if rotation != 0.0:
            watermark_with_opacity = watermark_with_opacity.rotate(
                -rotation, resample=Image.BICUBIC, expand=True
            )

        # Center on image
        rw, rh = watermark_with_opacity.size
        x = (img_width - rw) // 2
        y = (img_height - rh) // 2

        output = image.copy()
        output.paste(watermark_with_opacity, (x, y), watermark_with_opacity)
        return output
    
    def _apply_tile_watermark(
        self,
        image: Image.Image,
        watermark: Image.Image,
        scale: float,
        rotation: float = 0.0,
        tile_gap: int = 0,
        tile_stagger: bool = False
    ) -> Image.Image:
        """Apply tiled watermark with rotation, gap, and stagger support."""
        img_width, img_height = image.size

        wm_width = int(img_width * scale)
        wm_height = int(watermark.size[1] * (wm_width / watermark.size[0]))

        watermark_resized = watermark.resize((wm_width, wm_height), Image.LANCZOS)
        watermark_with_opacity = self._adjust_opacity(watermark_resized, self.watermark_opacity)

        # Rotate single tile
        if rotation != 0.0:
            watermark_with_opacity = watermark_with_opacity.rotate(
                -rotation, resample=Image.BICUBIC, expand=True
            )

        rw, rh = watermark_with_opacity.size
        spacing_x = rw + tile_gap
        spacing_y = rh + tile_gap

        output = image.copy()
        row_idx = 0
        for y in range(-rh, img_height + rh, spacing_y):
            x_offset = (spacing_x // 2) if (tile_stagger and row_idx % 2 == 1) else 0
            for x in range(-rw + x_offset, img_width + rw, spacing_x):
                output.paste(watermark_with_opacity, (x, y), watermark_with_opacity)
            row_idx += 1

        return output
    
    def _adjust_opacity(
        self,
        image: Image.Image,
        opacity: float
    ) -> Image.Image:
        """
        调整图片不透明度
        
        Args:
            image: 原始图片（RGBA模式）
            opacity: 不透明度 (0.0-1.0)
            
        Returns:
            调整后的图片
        """
        if image.mode != 'RGBA':
            image = image.convert('RGBA')
        
        # 复制图片并调整 Alpha 通道
        img_copy = image.copy()
        alpha = img_copy.split()[3]
        alpha = alpha.point(lambda p: int(p * opacity))
        img_copy.putalpha(alpha)
        
        return img_copy
    
    def save_preview_version(
        self,
        image: Image.Image,
        output_path: Path,
        watermark_path: Optional[Path] = None,
        watermark_mode: WatermarkMode = WatermarkMode.CENTER,
        watermark_scale: float = 0.4,
        watermark_rotation: float = 0.0,
        tile_gap: int = 0,
        tile_stagger: bool = False
    ) -> Path:
        """Save preview version (resized + optional watermark)."""
        try:
            preview = self.resize_image(image, self.preview_max_size)

            if watermark_path:
                preview = self.apply_watermark(
                    preview, watermark_path, watermark_mode,
                    scale=watermark_scale, rotation=watermark_rotation,
                    tile_gap=tile_gap, tile_stagger=tile_stagger
                )

            output_path.parent.mkdir(parents=True, exist_ok=True)
            preview.save(output_path, format='PNG', compress_level=6)
            return output_path

        except Exception as e:
            raise PackerError(f"保存预览版失败: {str(e)}")
    
    def save_thumbnail(
        self,
        image: Image.Image,
        output_path: Path
    ) -> Path:
        """
        保存缩略图
        
        Args:
            image: 原始图片
            output_path: 输出文件路径
            
        Returns:
            保存的文件路径
        """
        try:
            # 调整尺寸
            thumbnail = self.resize_image(image, self.thumbnail_max_size)
            
            # 确保输出目录存在
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 保存为 JPEG（缩略图不需要透明度，减小文件体积）
            # 如果有 Alpha 通道，先转换为 RGB
            if thumbnail.mode == 'RGBA':
                # 创建白色背景
                background = Image.new('RGB', thumbnail.size, (255, 255, 255))
                background.paste(thumbnail, mask=thumbnail.split()[3])
                thumbnail = background
            elif thumbnail.mode != 'RGB':
                thumbnail = thumbnail.convert('RGB')
            
            thumbnail.save(output_path, format='JPEG', quality=85, optimize=True)
            return output_path
            
        except Exception as e:
            raise PackerError(f"保存缩略图失败: {str(e)}")
    
    def process_image(
        self,
        input_path: Path,
        watermark_path: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        watermark_mode: WatermarkMode = WatermarkMode.CENTER,
        progress_callback: Optional[Callable[[str], None]] = None,
        watermark_scale: float = 0.4,
        watermark_rotation: float = 0.0,
        tile_gap: int = 0,
        tile_stagger: bool = False
    ) -> Tuple[Path, dict]:
        """
        一键打包处理图片（生成所有版本）
        
        Args:
            input_path: 输入图片路径
            watermark_path: 水印文件路径（可选）
            output_dir: 输出目录（可选，默认创建时间戳文件夹）
            watermark_mode: 水印模式
            progress_callback: 进度回调函数（可选）
            
        Returns:
            (输出目录路径, 输出文件信息字典)
            
        Raises:
            PackerError: 处理失败时抛出
        """
        try:
            def log(message: str):
                if progress_callback:
                    progress_callback(message)

            log("开始处理...")

            log(f"正在加载图片: {input_path.name}")
            image = self.load_image(input_path)
            log(f"图片已加载 ({image.size[0]}x{image.size[1]})")

            # Determine output path
            if output_dir is None:
                output_dir = input_path.parent
            output_dir.mkdir(parents=True, exist_ok=True)

            base_name = input_path.stem
            result = image.copy()

            # 1. Apply visible watermark
            if watermark_path:
                log("正在应用水印...")
                result = self.apply_watermark(
                    result, watermark_path, watermark_mode,
                    scale=watermark_scale, rotation=watermark_rotation,
                    tile_gap=tile_gap, tile_stagger=tile_stagger
                )

            # 2. Apply invisible watermark
            if self.protection_level != "none":
                log("正在嵌入隐形水印...")
                result = protect_image(result, self.protection_level, self.copyright_info)

            # 3. Save single output
            suffix = "_wm" if watermark_path else "_pack"
            out_path = output_dir / f"{base_name}{suffix}.png"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            save_with_watermark(result, str(out_path))

            results = {'output': out_path}
            log(f"完成: {out_path.name}")

            return output_dir, results

        except PackerError:
            raise
        except Exception as e:
            raise PackerError(f"处理图片失败: {str(e)}")


def create_text_watermark(
    text: str,
    font_size: int = 72,
    color: Tuple[int, int, int] = (255, 255, 255),
    output_path: Optional[Path] = None,
    bold: bool = False,
    italic: bool = False
) -> Path:
    """
    Create a text watermark image.

    Args:
        text: Watermark text
        font_size: Font size in pixels
        color: Text color (R, G, B)
        output_path: Output path (optional, auto-generated if None)
        bold: Use bold font variant
        italic: Use italic font variant
    """
    try:
        img_width = len(text) * font_size
        img_height = int(font_size * 1.5)

        img = Image.new('RGBA', (img_width, img_height), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        # Pick font variant based on bold/italic
        font_candidates = []
        if bold and italic:
            font_candidates = ["arialbi.ttf", "ariblk.ttf", "ariali.ttf", "arial.ttf"]
        elif bold:
            font_candidates = ["arialbd.ttf", "ariblk.ttf", "arial.ttf"]
        elif italic:
            font_candidates = ["ariali.ttf", "arial.ttf"]
        else:
            font_candidates = ["arial.ttf"]

        font = None
        for fname in font_candidates:
            try:
                font = ImageFont.truetype(fname, font_size)
                break
            except OSError:
                continue
        if font is None:
            font = ImageFont.load_default()

        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        x = (img_width - text_width) // 2
        y = (img_height - text_height) // 2

        draw.text((x, y), text, fill=(*color, 255), font=font)

        # Crop to actual text bounds
        text_bbox = img.getbbox()
        if text_bbox:
            img = img.crop(text_bbox)

        if output_path is None:
            output_path = Path(f"watermark_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")

        img.save(output_path, format='PNG')
        return output_path

    except Exception as e:
        raise PackerError(f"创建文字水印失败: {str(e)}")



