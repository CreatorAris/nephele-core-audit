"""
Nephele Workshop - 数字存证打包器
处理批量文件打包、清单生成、缩略图生成

Developer: ArisFusion Studio
"""

import json
import zipfile
import hashlib
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from PIL import Image
import io

try:
    import pyzipper
    PYZIPPER_AVAILABLE = True
except ImportError:
    PYZIPPER_AVAILABLE = False


class RightsPacker:
    """
    数字存证打包器
    
    功能：
    - 生成 manifest.json（包含作者、作品信息）
    - 生成缩略图拼贴（thumbnail.jpg）
    - 创建密码保护的 .nep 文件包
    """
    
    def __init__(self, output_path: Path, password: Optional[str] = None):
        """
        初始化打包器
        
        Args:
            output_path: 输出 .nep 文件路径
            password: ZIP 密码（可选）
        """
        self.output_path = Path(output_path)
        if self.output_path.suffix != '.nep':
            self.output_path = self.output_path.with_suffix('.nep')
        
        self.password = password.encode('utf-8') if password else None
        self.manifest_data = {}
    
    def create_manifest(
        self,
        author_name: str,
        inspiration: Optional[str] = None,
        works: List[Dict] = None,
        file_hashes: Dict[str, str] = None
    ) -> Dict:
        """
        创建清单数据

        Args:
            author_name: 作者名称
            inspiration: 创作灵感（可选）
            works: 作品列表 [{'title': str, 'creation_date': str, 'file_path': str}]
            file_hashes: 文件哈希字典 {文件路径: 哈希值}

        Returns:
            清单数据字典
        """
        self.manifest_data = {
            'version': '1.0',
            'created_at': datetime.now().isoformat(),
            'author': {
                'name': author_name,
                'inspiration': inspiration
            },
            'works': works or [],
            'file_hashes': file_hashes or {},
            'total_files': len(file_hashes) if file_hashes else 0
        }
        
        return self.manifest_data
    
    def generate_thumbnail(
        self,
        image_paths: List[Path],
        output_path: Path,
        grid_size: tuple = (4, 4),
        thumbnail_size: tuple = (200, 200)
    ) -> Path:
        """
        生成缩略图拼贴
        
        Args:
            image_paths: 图片文件路径列表
            output_path: 输出缩略图路径
            grid_size: 网格大小 (cols, rows)，默认 4x4 = 16 张
            thumbnail_size: 每张缩略图大小 (width, height)
        
        Returns:
            生成的缩略图路径
        """
        cols, rows = grid_size
        max_images = cols * rows
        
        # 限制图片数量
        image_paths = image_paths[:max_images]
        
        # 创建画布
        canvas_width = cols * thumbnail_size[0]
        canvas_height = rows * thumbnail_size[1]
        canvas = Image.new('RGB', (canvas_width, canvas_height), color='white')
        
        # 处理每张图片
        for idx, img_path in enumerate(image_paths):
            if not img_path.exists():
                continue
            
            try:
                # 打开并调整大小
                img = Image.open(img_path)
                img.thumbnail(thumbnail_size, Image.Resampling.LANCZOS)
                
                # 计算位置
                col = idx % cols
                row = idx // cols
                x = col * thumbnail_size[0]
                y = row * thumbnail_size[1]
                
                # 居中粘贴
                paste_x = x + (thumbnail_size[0] - img.width) // 2
                paste_y = y + (thumbnail_size[1] - img.height) // 2
                
                canvas.paste(img, (paste_x, paste_y))
            except Exception:
                # 如果图片无法打开，跳过
                continue
        
        # 保存
        canvas.save(output_path, 'JPEG', quality=85)
        return output_path
    
    def pack(
        self,
        manifest_data: Dict,
        thumbnail_path: Optional[Path] = None,
        timestamp_file: Optional[Path] = None,
        pdf_report: Optional[Path] = None,
        additional_files: List[Path] = None,
        source_files: List[Path] = None,
    ) -> Path:
        """
        打包所有文件为 .nep 格式

        Args:
            manifest_data: 清单数据
            thumbnail_path: 缩略图路径
            timestamp_file: 时间戳文件路径
            pdf_report: PDF 报告路径
            additional_files: 额外文件列表
            source_files: 原始作品文件（打包进 works/ 目录，验证时重算哈希比对）

        Returns:
            生成的 .nep 文件路径
        """
        # 确保输出目录存在
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        args = (manifest_data, thumbnail_path, timestamp_file,
                pdf_report, additional_files, source_files)

        # 根据是否需要密码保护选择不同的 ZIP 实现
        if self.password and PYZIPPER_AVAILABLE:
            with pyzipper.AESZipFile(
                self.output_path, 'w',
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES
            ) as zipf:
                zipf.setpassword(self.password)
                self._write_zip_contents(zipf, *args)
        elif self.password and not PYZIPPER_AVAILABLE:
            manifest_data = dict(manifest_data)
            manifest_data['_warning'] = (
                '密码保护未生效：需安装 pyzipper 库 (pip install pyzipper) '
                '以启用 AES-256 加密'
            )
            args = (manifest_data, thumbnail_path, timestamp_file,
                    pdf_report, additional_files, source_files)
            with zipfile.ZipFile(self.output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                self._write_zip_contents(zipf, *args)
        else:
            with zipfile.ZipFile(self.output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                self._write_zip_contents(zipf, *args)

        return self.output_path

    @staticmethod
    def _write_zip_contents(zipf, manifest_data, thumbnail_path, timestamp_file,
                            pdf_report, additional_files, source_files):
        """将内容写入 ZIP 文件（供 pack() 内部使用）"""
        # 1. 添加 manifest.json
        manifest_json = json.dumps(manifest_data, indent=2, ensure_ascii=False)
        zipf.writestr('manifest.json', manifest_json.encode('utf-8'))

        # 2. 添加缩略图
        if thumbnail_path and thumbnail_path.exists():
            zipf.write(thumbnail_path, 'thumbnail.jpg')

        # 3. 添加时间戳文件（保持原始扩展名：.tsa=RFC 3161 二进制，.json=本地降级）
        if timestamp_file and timestamp_file.exists():
            archive_name = 'proof.tsa' if timestamp_file.suffix == '.tsa' else 'proof.json'
            zipf.write(timestamp_file, archive_name)

        # 4. 添加 PDF 报告
        if pdf_report and pdf_report.exists():
            zipf.write(pdf_report, 'VerificationReport.pdf')

        # 5. 原始作品文件 → works/ 目录
        # Use indexed filenames (e.g. works/000_photo.jpg) to avoid collisions
        # when multiple source files share the same basename.  Must match the
        # indexed keys in manifest_data['works_map'].
        if source_files:
            for idx, file_path in enumerate(source_files):
                if isinstance(file_path, str):
                    file_path = Path(file_path)
                if file_path.exists() and file_path.is_file():
                    zipf.write(file_path, f'works/{idx:03d}_{file_path.name}')

        # 6. 添加额外文件
        if additional_files:
            for file_path in additional_files:
                if file_path.exists():
                    zipf.write(file_path, f'additional/{file_path.name}')

    def calculate_package_hash(self) -> str:
        """
        计算 .nep 文件包的哈希值（用于验证）
        
        Returns:
            文件包的 SHA256 哈希值
        """
        if not self.output_path.exists():
            raise ValueError(f"文件包不存在: {self.output_path}")
        
        hash_obj = hashlib.sha256()
        with open(self.output_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
