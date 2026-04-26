"""AI Metadata Detection Worker"""
import logging
from pathlib import Path
from PySide6.QtCore import QThread, Signal, QCoreApplication

_tr = QCoreApplication.translate

logger = logging.getLogger(__name__)


class AIDetectorWorker(QThread):
    """Worker thread for AI metadata detection."""

    progress = Signal(int, int, str)  # (current, total, filename)
    item_finished = Signal(str, str, str, str, str)  # (path, status, reason, tool, evidence)
    all_finished = Signal()
    model_status = Signal(str)  # Status for DynamicIsland

    def __init__(self, file_paths: list):
        super().__init__()
        self.file_paths = file_paths

    def run(self):
        """Execute metadata detection in background thread."""
        try:
            from .._utils import ensure_src_path
            ensure_src_path()
            
            from tools.validator.logic import MetaDataDetector
            detector = MetaDataDetector()

            self.model_status.emit(_tr("AIDetectorWorker", "扫描元数据..."))

            total = len(self.file_paths)
            logger.info("开始检测 %d 个文件", total)

            for i, path in enumerate(self.file_paths):
                if self.isInterruptionRequested():
                    break

                filename = Path(path).name
                self.progress.emit(i + 1, total, filename)

                try:
                    res = detector.detect(path)
                    self.item_finished.emit(
                        path,
                        res["status"],
                        res["reason"],
                        res["tool"] or "",
                        res["evidence"] or ""
                    )
                except Exception as e:
                    logger.error("[MetaDetector] 检测文件出错 %s: %s", path, e)
                    self.item_finished.emit(path, "error", _tr("AIDetectorWorker", "检测出错: %s") % str(e), "", "")

            logger.info("[MetaDetector] 检测完成，共 %d 个文件", total)

        except Exception as e:
            logger.error("[MetaDetector] Worker error: %s", e, exc_info=True)
        finally:
            self.all_finished.emit()

