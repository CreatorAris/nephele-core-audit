"""Watermark Extraction Worker"""
from pathlib import Path
from PySide6.QtCore import QThread, Signal, QCoreApplication

_tr = QCoreApplication.translate

from .._utils import ensure_src_path


class WatermarkExtractWorker(QThread):
    """Worker thread for watermark extraction (rivaGan model loading is slow)."""
    finished = Signal(str)  # watermark result or empty string
    logMessage = Signal(str, str)  # (message, level)

    def __init__(self, image_path: str):
        super().__init__()
        self.image_path = image_path

    def run(self):
        """Extract watermark in background thread."""
        try:
            ensure_src_path()

            from PIL import Image
            from tools.packer.watermark_protection import extract_watermark

            img_path = Path(self.image_path)
            if not img_path.exists():
                self.logMessage.emit(_tr("WatermarkExtractWorker", "文件不存在: %s") % self.image_path, "error")
                self.finished.emit("")
                return

            self.logMessage.emit(_tr("WatermarkExtractWorker", "正在提取水印: %s") % img_path.name, "info")

            image = Image.open(img_path)
            watermark = extract_watermark(image)

            if watermark:
                self.logMessage.emit(_tr("WatermarkExtractWorker", "提取成功: %s") % watermark, "success")
                self.finished.emit(watermark)
            else:
                self.logMessage.emit("未检测到隐形水印", "warning")
                self.finished.emit("")

        except Exception as e:
            self.logMessage.emit(f"提取失败: {str(e)}", "error")
            self.finished.emit("")
