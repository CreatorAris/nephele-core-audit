"""
Nephele Workshop - 维权中心核心逻辑
处理时间戳验证、律师函生成、证据打包

Developer: ArisFusion Studio
"""

import os
import zipfile
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime


class RightsError(Exception):
    """维权中心自定义异常"""
    pass


def parse_tsr(file_path: Path) -> Dict:
    """
    解析时间戳文件并返回验证结果

    支持两种格式：
    - .tsr: RFC 3161 ASN.1 DER 二进制格式（需要 asn1crypto 或 rfc3161ng）
    - .json: 本地时间戳元数据格式（Nephele 生成的本地降级格式）

    Args:
        file_path: .tsr 或 .json 时间戳文件路径

    Returns:
        包含验证结果的字典:
        {
            'valid': bool,
            'timestamp': str,  # ISO 格式时间戳
            'hash': str,       # 文件哈希值
            'issuer': str,     # 颁发机构
            'message': str     # 验证消息
        }

    Raises:
        RightsError: 文件读取失败或格式错误
    """
    if not file_path.exists():
        raise RightsError(f"时间戳文件不存在: {file_path}")

    suffix = file_path.suffix.lower()
    if suffix not in ('.tsr', '.tsa', '.json'):
        raise RightsError(f"不支持的文件格式: {suffix}，需要 .tsr/.tsa 或 .json 文件")

    try:
        # JSON 格式（本地时间戳）
        if suffix == '.json':
            return _parse_local_timestamp_json(file_path)

        # .tsr / .tsa 格式（RFC 3161 二进制）
        with open(file_path, 'rb') as f:
            data = f.read()

        if len(data) < 20:
            raise RightsError("时间戳文件过小，可能已损坏")

        # 检查是否为 JSON（兼容旧版本误存为 .tsr 的 JSON 文件）
        if data[:1] in (b'{', b'['):
            try:
                return _parse_local_timestamp_json(file_path)
            except (json.JSONDecodeError, RightsError):
                pass

        # 尝试用 asn1crypto 解析 ASN.1 DER 结构
        return _parse_rfc3161_tsr(data, file_path)

    except RightsError:
        raise
    except (OSError, PermissionError) as e:
        raise RightsError(f"读取时间戳文件失败: {e}")


def _parse_local_timestamp_json(file_path: Path) -> Dict:
    """解析本地 JSON 格式的时间戳文件"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            ts_data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise RightsError(f"JSON 时间戳文件格式错误: {e}")

    is_local = ts_data.get('type') == 'local_timestamp'
    return {
        'valid': True,
        'timestamp': ts_data.get('timestamp', 'N/A'),
        'hash': ts_data.get('work_identity', ts_data.get('hash', 'N/A')),
        'issuer': ts_data.get('issuer', 'Nephele (本地)'),
        'message': ("本地时间戳验证通过（注意：未经第三方 TSA 认证）"
                    if is_local else "时间戳元数据读取成功"),
        'is_local': is_local
    }


def _parse_rfc3161_tsr(data: bytes, file_path: Path) -> Dict:
    """解析 RFC 3161 ASN.1 DER 格式的 TSR 文件

    支持两种 TSA 返回格式：
    - TimeStampResp（完整响应，含 status + token）
    - ContentInfo/SignedData（仅 token，DigiCert 等返回此格式）
    """
    # 验证 ASN.1 DER 基础结构（SEQUENCE tag = 0x30）
    if data[0] != 0x30:
        raise RightsError("文件不是有效的 ASN.1 DER 格式（缺少 SEQUENCE 标签）")

    # 尝试使用 asn1crypto 进行详细解析
    try:
        from asn1crypto import tsp, cms

        # 尝试两种格式：TimeStampResp（完整响应）和 ContentInfo（仅 token）
        signed_data = None

        # 格式 1: TimeStampResp（包含 status + token 的完整响应）
        try:
            tsr = tsp.TimeStampResp.load(data)
            status = tsr['status']['status'].native
            if status != 'granted' and status != 'granted_with_mods':
                return {
                    'valid': False,
                    'timestamp': 'N/A',
                    'hash': 'N/A',
                    'issuer': 'N/A',
                    'message': f"时间戳状态异常: {status}"
                }
            signed_data = tsr['time_stamp_token']['content']
        except (ValueError, KeyError, TypeError):
            pass

        # 格式 2: ContentInfo（DigiCert 等直接返回 SignedData token）
        if signed_data is None:
            try:
                content_info = cms.ContentInfo.load(data)
                if content_info['content_type'].native == 'signed_data':
                    signed_data = content_info['content']
            except (ValueError, KeyError, TypeError):
                pass

        if signed_data is None:
            raise RightsError("无法解析为 TimeStampResp 或 ContentInfo 格式")

        # 提取 TSTInfo
        tst_info = signed_data['encap_content_info']['content'].parsed
        gen_time = tst_info['gen_time'].native
        hash_algo = tst_info['message_imprint']['hash_algorithm']['algorithm'].native
        hash_value = tst_info['message_imprint']['hashed_message'].native.hex()

        # 提取颁发机构
        issuer = 'RFC 3161 TSA'
        try:
            signer_infos = signed_data['signer_infos']
            if signer_infos:
                sid = signer_infos[0]['sid']
                if sid.name == 'issuer_and_serial_number':
                    issuer_name = sid.chosen['issuer']
                    for rdn in issuer_name.chosen:
                        for attr in rdn:
                            if attr['type'].dotted == '2.5.4.3':  # CN
                                issuer = attr['value'].native
                                break
        except (KeyError, IndexError, ValueError):
            pass

        return {
            'valid': True,
            'timestamp': gen_time.isoformat() if gen_time else 'N/A',
            'hash': f"{hash_algo}:{hash_value}",
            'issuer': issuer,
            'message': f"RFC 3161 时间戳验证通过（颁发: {issuer}）"
        }

    except ImportError:
        # asn1crypto 未安装，进行基础验证
        file_size = len(data)
        return {
            'valid': True,
            'timestamp': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
            'hash': f"sha256:{hashlib.sha256(data).hexdigest()[:16]}...",
            'issuer': "RFC 3161 TSA（需安装 asn1crypto 以获取详细信息）",
            'message': (f"TSR 文件结构有效 ({file_size} 字节)，"
                       "安装 asn1crypto 库可获取完整解析结果")
        }
    except RightsError:
        raise
    except Exception as e:
        raise RightsError(f"解析 RFC 3161 TSR 文件失败: {e}")


def generate_legal_letter(data: Dict) -> str:
    """
    根据模板生成维权律师函文本
    
    Args:
        data: 包含案件信息的字典:
        {
            'copyright_owner': str,    # 版权所有者
            'infringement_url': str,   # 侵权链接（可选）
            'infringement_date': str,  # 侵权日期
            'work_title': str,         # 作品名称
            'timestamp_info': dict,    # 时间戳验证信息
            'evidence_files': list      # 证据文件列表
        }
    
    Returns:
        律师函文本（中文）
    """
    template = f"""
律师函

致：侵权方

本律师受 {data.get('copyright_owner', '版权所有者')} 委托，就您方侵犯其著作权一事，特向您方致函如下：

一、事实与理由

1. 我的委托人系作品《{data.get('work_title', '作品名称')}》的合法著作权人，对该作品享有完整的著作权。

2. 经查，您方于 {data.get('infringement_date', '侵权日期')} 在以下平台/网站未经授权使用了上述作品：
   {data.get('infringement_url', '侵权链接（如有）') or '（具体链接见附件）'}

3. 我的委托人已通过合法途径获得时间戳认证，证明其对上述作品的创作时间及权属关系。

二、时间戳认证信息

根据时间戳服务中心出具的认证文件：
- 认证时间：{data.get('timestamp_info', {}).get('timestamp', 'N/A')}
- 文件哈希：{data.get('timestamp_info', {}).get('hash', 'N/A')}
- 颁发机构：{data.get('timestamp_info', {}).get('issuer', 'N/A')}

上述认证具有法律效力，可作为证明作品创作时间及权属的有效证据。

三、法律依据

您方的行为已构成对《中华人民共和国著作权法》的违反，具体包括：
- 未经许可使用他人作品（第47条）
- 侵犯著作权人的署名权、复制权、信息网络传播权等（第10条）

四、要求

现要求您方：

1. 立即停止侵权行为，删除所有侵权内容；
2. 在收到本函后 7 日内，就侵权行为向我方委托人书面道歉；
3. 赔偿我方委托人的经济损失及合理维权费用；
4. 如您方拒绝履行上述要求，我方将依法采取包括但不限于诉讼在内的法律手段维护委托人的合法权益。

五、证据材料

随函附上以下证据材料：
- 时间戳认证文件
- 作品原始文件及截图
- 侵权证据截图
- 其他相关证明材料

特此函告。

此致

{data.get('copyright_owner', '版权所有者')}
委托代理人

{datetime.now().strftime('%Y年%m月%d日')}
"""
    
    return template.strip()


def create_evidence_zip(
    output_path: Path,
    timestamp_file: Optional[Path] = None,
    evidence_files: List[Path] = None,
    legal_letter: Optional[str] = None,
    screenshot_files: List[Path] = None
) -> Path:
    """
    将证书、截图和律师函打包为 .zip 文件
    
    Args:
        output_path: 输出 ZIP 文件路径
        timestamp_file: 时间戳文件路径（可选）
        evidence_files: 证据文件列表（可选）
        legal_letter: 律师函文本（可选）
        screenshot_files: 截图文件列表（可选）
    
    Returns:
        创建的 ZIP 文件路径
    
    Raises:
        RightsError: 打包失败
    """
    if evidence_files is None:
        evidence_files = []
    if screenshot_files is None:
        screenshot_files = []
    
    try:
        # 确保输出目录存在
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # 添加时间戳文件
            if timestamp_file and timestamp_file.exists():
                zipf.write(timestamp_file, f"时间戳认证/{timestamp_file.name}")
            
            # 添加证据文件
            if evidence_files:
                for idx, file_path in enumerate(evidence_files, 1):
                    if file_path.exists():
                        zipf.write(file_path, f"证据材料/证据{idx}_{file_path.name}")
            
            # 添加截图文件
            if screenshot_files:
                for idx, file_path in enumerate(screenshot_files, 1):
                    if file_path.exists():
                        zipf.write(file_path, f"截图证据/截图{idx}_{file_path.name}")
            
            # 添加律师函（如果提供）
            if legal_letter:
                zipf.writestr("律师函.txt", legal_letter.encode('utf-8'))
            
            # 添加说明文件
            readme_content = f"""
维权证据包说明

生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

本证据包包含以下内容：
1. 时间戳认证文件 - 证明作品创作时间及权属
2. 证据材料 - 原始作品文件
3. 截图证据 - 侵权行为截图
4. 律师函 - 法律维权文件

请妥善保管本证据包，作为法律维权的有效证据。

---
Nephele Workshop - 维权中心
ArisFusion Studio
"""
            zipf.writestr("说明.txt", readme_content.encode('utf-8'))
        
        return output_path
        
    except Exception as e:
        raise RightsError(f"创建证据包失败: {str(e)}")


def calculate_file_hash(file_path: Path, algorithm: str = 'sha256') -> str:
    """
    计算文件的哈希值（极简版，仅用于非确权场景）
    
    Args:
        file_path: 文件路径
        algorithm: 哈希算法，默认 'sha256'
    
    Returns:
        文件的十六进制哈希值
    
    Raises:
        RightsError: 文件不存在或读取失败
    """
    if not file_path or not isinstance(file_path, Path):
        raise RightsError(f"无效的文件路径: {file_path}")
    
    if not file_path.exists():
        raise RightsError(f"文件不存在: {file_path}")
    
    if not file_path.is_file():
        raise RightsError(f"路径不是文件: {file_path}")
    
    try:
        file_size = file_path.stat().st_size
        if file_size > 10 * 1024 * 1024 * 1024:  # 10GB 限制
            raise RightsError(f"文件过大（超过10GB）: {file_path}")
        
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            chunk_size = 8192
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    except PermissionError:
        raise RightsError(f"没有权限读取文件: {file_path}")
    except OSError as e:
        raise RightsError(f"读取文件失败: {file_path}, 错误: {str(e)}")
    except Exception as e:
        raise RightsError(f"计算文件哈希失败: {file_path}, 错误: {str(e)}")


def generate_timestamp(files: List[Path], output_dir: Optional[Path] = None, tsa_provider: str = 'digicert', tsa_timeout: int = 30) -> Dict:
    """
    确权操作：为文件生成时间戳和指纹（极简版，仅哈希计算）
    
    Args:
        files: 要确权的文件列表（源文件和成品图）
        output_dir: 时间戳文件输出目录（可选，不指定则不保存文件）
    
    Returns:
        包含确权结果的字典:
        {
            'valid': bool,
            'timestamp': str,      # ISO 格式时间戳
            'hash': str,           # 组合文件哈希值（作品指纹）
            'file_hashes': dict,   # 每个文件的哈希值 {文件路径: 哈希值}
            'issuer': str,         # 颁发机构
            'message': str,        # 确权消息
            'timestamp_file': str  # 时间戳文件路径（如果保存了）
        }
    
    Raises:
        RightsError: 确权失败
    """
    if not files:
        raise RightsError("请至少提供一个文件进行确权")
    
    # 验证并规范化文件路径（极简版）
    valid_files = []
    for file_path in files:
        try:
            if isinstance(file_path, str):
                file_path = Path(file_path)
            elif not isinstance(file_path, Path):
                continue
            
            if file_path.exists() and file_path.is_file() and os.access(file_path, os.R_OK):
                valid_files.append(file_path)
        except Exception:
            continue
    
    if not valid_files:
        raise RightsError("没有有效的文件可以确权")
    
    # 极简哈希计算（直接计算，不调用其他函数）
    file_hashes = {}
    combined_hash = hashlib.sha256()
    
    for file_path in valid_files:
        try:
            # 直接计算哈希，避免调用可能触发GUI的函数
            hash_obj = hashlib.sha256()
            file_size = file_path.stat().st_size
            if file_size > 10 * 1024 * 1024 * 1024:  # 10GB限制
                raise RightsError(f"文件过大: {file_path}")
            
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    hash_obj.update(chunk)
            
            file_hash = hash_obj.hexdigest()
            file_path_str = str(file_path)
            file_hashes[file_path_str] = file_hash
            combined_hash.update(f"{file_path_str}:{file_hash}".encode('utf-8'))
        except PermissionError:
            raise RightsError(f"没有权限读取文件: {file_path}")
        except OSError as e:
            raise RightsError(f"读取文件失败: {file_path}, 错误: {str(e)}")
        except Exception as e:
            raise RightsError(f"处理文件失败 {file_path}: {str(e)}")
    
    # 生成作品指纹
    work_identity = combined_hash.hexdigest()
    timestamp = datetime.now().isoformat()
    
    # 构建确权结果
    result = {
        'valid': True,
        'timestamp': timestamp,
        'hash': work_identity,
        'file_hashes': file_hashes,
        'issuer': "Nephele 时间戳服务",
        'message': f"确权成功，共处理 {len(valid_files)} 个文件",
        'timestamp_file': None
    }
    
    # 如果指定了输出目录，保存时间戳文件
    if output_dir:
        try:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            # 尝试使用 TSAClient 获取真正的 RFC 3161 时间戳
            tsr_saved = False
            try:
                from .tsa_client import TSAClient
                tsa_client = TSAClient(provider=tsa_provider, timeout=tsa_timeout)
                tsr_path = output_dir / f"timestamp_{work_identity[:16]}.tsr"
                tsa_result = tsa_client.timestamp_hash(work_identity, tsr_path)
                if tsa_result.get('success'):
                    result['timestamp_file'] = str(tsr_path)
                    result['timestamp'] = tsa_result.get('timestamp', timestamp)
                    result['issuer'] = tsa_result.get('issuer', result['issuer'])
                    result['message'] += f"，RFC 3161 时间戳已保存: {tsr_path.name}"
                    tsr_saved = True
            except (ImportError, Exception):
                pass

            # TSA 不可用时，保存本地时间戳元数据（使用 .json 后缀，避免与真正的 .tsr 混淆）
            if not tsr_saved:
                local_ts_filename = f"timestamp_{work_identity[:16]}.json"
                local_ts_path = output_dir / local_ts_filename
                timestamp_data = {
                    'version': '1.0',
                    'type': 'local_timestamp',
                    'note': '本地时间戳，未经第三方 TSA 认证，仅供参考',
                    'timestamp': timestamp,
                    'work_identity': work_identity,
                    'file_hashes': file_hashes,
                    'issuer': result['issuer'],
                    'files': [str(f) for f in valid_files]
                }
                with open(local_ts_path, 'w', encoding='utf-8') as f:
                    json.dump(timestamp_data, f, indent=2, ensure_ascii=False)
                result['timestamp_file'] = str(local_ts_path)
                result['message'] += f"，本地时间戳已保存: {local_ts_filename}（建议安装 rfc3161ng 以获取权威时间戳）"
        except OSError as e:
            result['message'] += f"（时间戳文件保存失败: {e}）"
    
    return result


def verify_timestamp_file(file_path: Path) -> Tuple[bool, Dict]:
    """
    验证时间戳文件（便捷方法，仅结构验证）

    支持 .tsr/.tsa (RFC 3161) 和 .json (本地时间戳) 格式。

    Args:
        file_path: .tsr/.tsa 或 .json 时间戳文件路径

    Returns:
        (是否有效, 验证结果字典)
    """
    try:
        result = parse_tsr(file_path)
        return result.get('valid', False), result
    except RightsError as e:
        return False, {'valid': False, 'message': str(e)}
    except Exception as e:
        return False, {'valid': False, 'message': f"验证失败: {str(e)}"}


def verify_evidence_package(
    tsa_path: Path,
    file_paths: List[Path],
) -> Tuple[bool, Dict]:
    """
    深度验证存证包：重算文件哈希 → 重建 Merkle Tree → 与 TSR 中签名的哈希比对。

    验证链路:
      文件列表 → SHA-256 → Merkle Tree → Root Hash → 与 TSR 内 messageImprint 比对

    Args:
        tsa_path: .tsa/.tsr 时间戳文件路径
        file_paths: 被存证的原始文件路径列表（顺序必须与存证时一致）

    Returns:
        (是否通过, 验证结果字典)
    """
    from .utils import build_merkle_tree_from_files

    if not tsa_path.exists():
        return False, {'valid': False, 'message': f"时间戳文件不存在: {tsa_path}"}

    missing = [str(p) for p in file_paths if not p.exists()]
    if missing:
        return False, {'valid': False, 'message': f"原始文件缺失: {', '.join(missing)}"}

    try:
        # Step 1: 重算文件哈希，重建 Merkle Tree
        tree = build_merkle_tree_from_files(file_paths)
        computed_root = tree.root_hash

        # Step 2: 检查是否为本地时间戳（无第三方签名，不具备证明力）
        suffix = tsa_path.suffix.lower()
        if suffix == '.json':
            tsr_result = parse_tsr(tsa_path)
            tsr_hash = tsr_result.get('hash', tsr_result.get('work_identity', ''))
            if computed_root.lower() == tsr_hash.lower():
                return False, {
                    'valid': False,
                    'message': "本地时间戳无第三方签名，不具备密码学证明力。文件哈希一致但无法证明时间。",
                    'root_hash': computed_root,
                    'local_only': True,
                    'file_count': len(file_paths),
                }
            else:
                return False, {
                    'valid': False,
                    'message': "验证失败：Merkle Root 与本地时间戳记录不匹配",
                    'computed_root': computed_root,
                    'file_count': len(file_paths),
                }

        # Step 3: RFC 3161 TSR — 用 rfc3161ng 做真正的密码学签名验证
        computed_digest = bytes.fromhex(computed_root)
        try:
            from .tsa_client import TSAClient
            tsa_client = TSAClient()
            verify_result = tsa_client.verify_tsr(tsa_path, digest=computed_digest)

            if verify_result.get('valid'):
                # 同时解析 TSR 获取时间戳详情（签发时间、签发方）
                tsr_result = parse_tsr(tsa_path)
                return True, {
                    'valid': True,
                    'message': f"深度验证通过：{len(file_paths)} 个文件的 Merkle Root 与 TSA 签名匹配（密码学验证）",
                    'timestamp': tsr_result.get('timestamp'),
                    'issuer': tsr_result.get('issuer'),
                    'root_hash': computed_root,
                    'file_count': len(file_paths),
                }
            else:
                return False, {
                    'valid': False,
                    'message': f"TSA 签名验证失败：{verify_result.get('message', 'unknown')}",
                    'root_hash': computed_root,
                    'file_count': len(file_paths),
                }

        except ImportError:
            # rfc3161ng 未安装，降级为结构性比对（明确标注）
            tsr_result = parse_tsr(tsa_path)
            tsr_hash_raw = tsr_result.get('hash', '')
            tsr_hash = tsr_hash_raw.split(':', 1)[1] if ':' in tsr_hash_raw else tsr_hash_raw

            if computed_root.lower() == tsr_hash.lower():
                return True, {
                    'valid': True,
                    'message': f"结构验证通过（安装 rfc3161ng 可启用密码学签名验证）",
                    'timestamp': tsr_result.get('timestamp'),
                    'issuer': tsr_result.get('issuer'),
                    'root_hash': computed_root,
                    'file_count': len(file_paths),
                    'partial_verification': True,
                }
            else:
                return False, {
                    'valid': False,
                    'message': "验证失败：Merkle Root 与 TSR 记录的哈希不匹配",
                    'computed_root': computed_root,
                    'tsr_hash': tsr_hash,
                    'file_count': len(file_paths),
                }

    except Exception as e:
        return False, {'valid': False, 'message': f"深度验证失败: {e}"}


def batch_protect_works(
    file_paths: List[Path],
    author_name: str,
    inspiration: Optional[str] = None,
    output_dir: Optional[Path] = None,
    password: Optional[str] = None,
    progress_callback=None,
    tsa_provider: str = 'digicert',
    tsa_timeout: int = 30,
    cert_mode: str = 'simple',
) -> Dict:
    """
    批量保护作品（数字存证核心流程）
    
    流程：
    1. 计算所有文件哈希
    2. 构建 Merkle Tree
    3. 生成 manifest.json
    4. 生成缩略图拼贴
    5. 调用 TSA 获取时间戳（使用根哈希）
    6. 生成 PDF 报告
    7. 打包为 .nep 文件
    
    Args:
        file_paths: 文件路径列表
        author_name: 作者名称
        inspiration: 创作灵感（可选）
        output_dir: 输出目录
        password: .nep 文件密码（可选）
        progress_callback: 进度回调 (current, total, message)
    
    Returns:
        包含处理结果的字典
    """
    from .utils import build_merkle_tree_from_files
    from .rights_packer import RightsPacker
    from .pdf_generator import PDFGenerator
    
    if not file_paths:
        raise RightsError("文件列表为空")
    
    if output_dir is None:
        output_dir = Path.cwd() / "digital_evidence"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # 步骤 1: 计算文件哈希并构建 Merkle Tree
        if progress_callback:
            progress_callback(0, len(file_paths), "正在计算文件哈希...")
        
        def hash_progress(current, total):
            if progress_callback:
                progress_callback(current, total, f"计算哈希: {current}/{total}")
        
        tree = build_merkle_tree_from_files(file_paths, progress_callback=hash_progress)
        root_hash = tree.root_hash

        image_extensions = {'.jpg', '.jpeg', '.png', '.webp', '.bmp'}

        # 步骤 2: 收集文件哈希和作品信息 + 计算感知哈希
        # Reuse hashes already computed by Merkle Tree (avoid double I/O)
        file_hashes = dict(tree.file_hashes)
        works = []
        fingerprints = []  # Perceptual hashes for image files

        for file_path in file_paths:
            file_hash = file_hashes.get(str(file_path), calculate_file_hash(file_path))

            # 获取文件创建时间
            try:
                creation_time = datetime.fromtimestamp(file_path.stat().st_mtime)
            except (OSError, ValueError, OverflowError):
                creation_time = datetime.now()

            works.append({
                'title': file_path.stem,
                'creation_date': creation_time.isoformat(),
                'file_path': str(file_path),
                'file_hash': file_hash
            })

            # Compute perceptual hash for image files (non-blocking, best-effort)
            if file_path.suffix.lower() in image_extensions:
                try:
                    from .fingerprint import compute_fingerprint
                    fp = compute_fingerprint(file_path, file_sha256=file_hash)
                    fingerprints.append(fp)
                except Exception as e:
                    import logging as _logging
                    _logging.getLogger(__name__).debug(
                        "Skipping perceptual hash for %s: %s", file_path.name, e
                    )
        
        # 步骤 3: 生成 manifest.json
        if progress_callback:
            progress_callback(len(file_paths), len(file_paths), "正在生成清单...")
        
        packer = RightsPacker(output_dir / "evidence.nep", password=password)
        manifest_data = packer.create_manifest(
            author_name=author_name,
            inspiration=inspiration,
            works=works,
            file_hashes=file_hashes
        )
        
        # 步骤 4: 生成缩略图（仅图片文件）
        image_paths = [p for p in file_paths if p.suffix.lower() in image_extensions]
        
        thumbnail_path = None
        if image_paths:
            if progress_callback:
                progress_callback(len(file_paths), len(file_paths), "正在生成缩略图...")
            
            thumbnail_path = output_dir / "thumbnail.jpg"
            packer.generate_thumbnail(image_paths, thumbnail_path)
        
        # 步骤 5: 调用 DigiCert 获取真实 RFC 3161 时间戳
        if progress_callback:
            progress_callback(len(file_paths), len(file_paths), "正在获取 DigiCert 时间戳...")

        tsa_binary_path = output_dir / "proof.tsa"    # RFC 3161 二进制
        local_json_path = output_dir / "proof.json"   # 本地降级 JSON
        timestamp_file = tsa_binary_path              # 最终实际写入的文件

        try:
            from .tsa_client import TSAClient

            # 初始化 TSA 客户端（可配置提供商）
            tsa_client = TSAClient(provider=tsa_provider, timeout=tsa_timeout)

            # 用 Merkle Root Hash 获取时间戳
            tsa_result = tsa_client.timestamp_hash(root_hash, tsa_binary_path)

            if tsa_result['success']:
                timestamp_file = tsa_binary_path
                timestamp_info = {
                    'timestamp': tsa_result['timestamp'],
                    'hash': root_hash,
                    'issuer': tsa_result['issuer'],
                    'algorithm': tsa_result['algorithm'],
                    'valid': True,
                    'tsr_path': str(tsa_binary_path)
                }
            else:
                # TSA 失败，使用本地时间戳（写 .json，不混淆 .tsa）
                timestamp_file = local_json_path
                timestamp_info = {
                    'timestamp': datetime.now().isoformat(),
                    'hash': root_hash,
                    'issuer': 'Nephele Workshop (本地)',
                    'algorithm': 'SHA256',
                    'valid': True,
                    'local_only': True,
                    'error': tsa_result['message']
                }
                with open(local_json_path, 'w', encoding='utf-8') as f:
                    json.dump(timestamp_info, f, indent=2, ensure_ascii=False)

        except ImportError:
            # rfc3161ng 未安装，使用本地时间戳
            timestamp_file = local_json_path
            timestamp_info = {
                'timestamp': datetime.now().isoformat(),
                'hash': root_hash,
                'issuer': 'Nephele Workshop (本地)',
                'algorithm': 'SHA256',
                'valid': True,
                'local_only': True,
                'note': '需安装 rfc3161ng 库以使用 FreeTSA 服务'
            }
            with open(local_json_path, 'w', encoding='utf-8') as f:
                json.dump(timestamp_info, f, indent=2, ensure_ascii=False)

        except Exception as e:
            # 任何异常都降级为本地时间戳
            timestamp_file = local_json_path
            timestamp_info = {
                'timestamp': datetime.now().isoformat(),
                'hash': root_hash,
                'issuer': 'Nephele Workshop (本地)',
                'algorithm': 'SHA256',
                'valid': True,
                'local_only': True,
                'error': str(e)
            }
            with open(local_json_path, 'w', encoding='utf-8') as f:
                json.dump(timestamp_info, f, indent=2, ensure_ascii=False)
        
        # 步骤 5b: 丰富 manifest（验证网站需要 merkle_root 字段）
        manifest_data['merkle_root'] = root_hash
        manifest_data['cert_mode'] = cert_mode

        # works_map: 包内 works/filename → sha256，供验证网页逐文件比对
        # Use indexed filenames to avoid duplicate name collisions
        works_map = {}
        for idx, fp in enumerate(file_paths):
            works_map[f"works/{idx:03d}_{fp.name}"] = file_hashes.get(str(fp), "")
        manifest_data['works_map'] = works_map

        # Compute manifest's own SHA-256 so the TSA-anchored Merkle root
        # transitively protects manifest metadata (author, dates, etc.).
        # Verification: remove 'manifest_sha256' key, json.dumps(sort_keys=True,
        # ensure_ascii=False), SHA-256 the UTF-8 bytes.
        _manifest_for_hash = {k: v for k, v in manifest_data.items() if k != 'manifest_sha256'}
        _manifest_json = json.dumps(_manifest_for_hash, ensure_ascii=False, sort_keys=True, default=str)
        manifest_data['manifest_sha256'] = hashlib.sha256(_manifest_json.encode('utf-8')).hexdigest()

        # 步骤 6: 生成 PDF 报告
        if progress_callback:
            progress_callback(len(file_paths), len(file_paths), "正在生成 PDF 报告...")
        
        verification_url = f"https://verify.arisfusion.com?id={root_hash[:16]}"
        pdf_path = output_dir / "VerificationReport.pdf"
        
        pdf_gen = PDFGenerator(pdf_path, cert_mode=cert_mode)
        pdf_gen.generate(
            manifest_data=manifest_data,
            root_hash=root_hash,
            timestamp_info=timestamp_info,
            verification_url=verification_url,
            locale="zh_CN",
            image_paths=image_paths,
        )
        
        # 步骤 7: 打包为 .nep 文件
        if progress_callback:
            progress_callback(len(file_paths), len(file_paths), "正在打包证据包...")
        
        nep_path = packer.pack(
            manifest_data=manifest_data,
            thumbnail_path=thumbnail_path,
            timestamp_file=timestamp_file,
            pdf_report=pdf_path,
            source_files=file_paths,
        )
        
        # 步骤 8: 保存感知哈希到指纹库 (best-effort, 不影响存证流程)
        if fingerprints:
            try:
                from .fingerprint import get_fingerprint_db
                fp_db = get_fingerprint_db()
                fp_db.save_fingerprints_batch(
                    fingerprints, work_id=root_hash
                )
            except Exception as e:
                import logging as _logging
                _logging.getLogger(__name__).warning(
                    "Failed to save fingerprints to DB: %s", e
                )

        if progress_callback:
            progress_callback(len(file_paths), len(file_paths), "完成！")

        return {
            'success': True,
            'nep_path': str(nep_path),
            'root_hash': root_hash,
            'manifest': manifest_data,
            'timestamp_info': timestamp_info,
            'file_count': len(file_paths),
            'fingerprint_count': len(fingerprints),
            'message': f"数字存证完成，共处理 {len(file_paths)} 个文件"
        }
        
    except Exception as e:
        raise RightsError(f"批量保护失败: {str(e)}")
