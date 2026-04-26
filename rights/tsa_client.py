"""
Nephele Workshop - RFC 3161 Time Stamp Authority (TSA) 客户端
支持 FreeTSA 和其他 RFC 3161 兼容的时间戳服务

Developer: ArisFusion Studio
"""

import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import warnings

# 禁用 SSL 警告（仅用于兼容性，不影响安全性）
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

try:
    import rfc3161ng
    RFC3161_AVAILABLE = True
except ImportError:
    RFC3161_AVAILABLE = False


class TSAClient:
    """
    RFC 3161 时间戳服务客户端

    支持的服务：
    - FreeTSA (https://freetsa.org/tsr) - 免费，无需注册
    - DigiCert (http://timestamp.digicert.com)
    - IdenTrust (http://timestamp.identrust.com)
    - 其他 RFC 3161 兼容服务
    """

    # 预定义的 TSA 服务提供商
    PROVIDERS = {
        'freetsa': {
            'name': 'FreeTSA',
            'url': 'https://freetsa.org/tsr',
            'hashname': 'sha256',
            'description': '免费时间戳服务，国际标准 RFC 3161',
            'requires_auth': False,
            'legal_strength': 3,  # 1-5 评分
            'price': 0
        },
        'digicert': {
            'name': 'DigiCert',
            'url': 'http://timestamp.digicert.com',
            'hashname': 'sha256',
            'description': 'DigiCert 免费时间戳服务',
            'requires_auth': False,
            'legal_strength': 4,
            'price': 0
        },
        'identrust': {
            'name': 'IdenTrust',
            'url': 'http://timestamp.identrust.com',
            'hashname': 'sha256',
            'description': 'IdenTrust 免费时间戳服务',
            'requires_auth': False,
            'legal_strength': 4,
            'price': 0
        }
    }

    def __init__(
        self,
        provider: str = 'freetsa',
        custom_url: Optional[str] = None,
        hashname: str = 'sha256',
        timeout: int = 30
    ):
        """
        初始化 TSA 客户端

        Args:
            provider: 预定义的服务提供商名称 ('freetsa', 'digicert', 'identrust')
            custom_url: 自定义 TSA URL（如果指定，则忽略 provider）
            hashname: 哈希算法 ('sha256', 'sha512' 等)
            timeout: 请求超时时间（秒）
        """
        if not RFC3161_AVAILABLE:
            raise ImportError(
                "rfc3161ng 库未安装。请运行: pip install rfc3161ng"
            )

        if custom_url:
            self.url = custom_url
            self.provider_name = "Custom TSA"
            self.provider_key = None
        elif provider in self.PROVIDERS:
            config = self.PROVIDERS[provider]
            self.url = config['url']
            self.provider_name = config['name']
            self.provider_key = provider
            hashname = config['hashname']
        else:
            raise ValueError(
                f"未知的 TSA 提供商: {provider}。"
                f"支持的提供商: {', '.join(self.PROVIDERS.keys())}"
            )

        self.hashname = hashname
        self.timeout = timeout

        # 初始化 rfc3161ng 时间戳器
        # 注意：某些环境可能遇到 SSL 握手问题，这是正常的
        # 我们的设计会自动降级到本地哈希
        try:
            self.stamper = rfc3161ng.RemoteTimestamper(
                url=self.url,
                hashname=self.hashname,
                timeout=self.timeout
            )
        except Exception as e:
            # 如果初始化失败，记录错误但不抛出异常
            # 后续调用时会返回失败状态
            self.stamper = None
            self._init_error = str(e)

    FAILOVER_ORDER: List[str] = ['digicert', 'freetsa', 'identrust']

    def _call_with_retry(self, hash_bytes: bytes, max_retries: int = 3) -> bytes:
        """
        带指数退避和提供商故障转移的 TSA 调用

        Args:
            hash_bytes: 要签名的哈希值（二进制）
            max_retries: 每个提供商的最大重试次数

        Returns:
            TSR 令牌（二进制）

        Raises:
            Exception: 所有提供商均失败
        """
        # 构建尝试顺序：当前提供商优先，然后是其他提供商
        providers_to_try = []
        if self.provider_key:
            providers_to_try.append(self.provider_key)
            for p in self.FAILOVER_ORDER:
                if p != self.provider_key:
                    providers_to_try.append(p)
        else:
            # 自定义 URL，无故障转移
            providers_to_try = [None]

        last_error = None
        for provider_key in providers_to_try:
            if provider_key is not None:
                config = self.PROVIDERS[provider_key]
                url = config['url']
                hashname = config['hashname']
                provider_name = config['name']
            else:
                url = self.url
                hashname = self.hashname
                provider_name = self.provider_name

            for attempt in range(max_retries):
                try:
                    stamper = rfc3161ng.RemoteTimestamper(
                        url=url,
                        hashname=hashname,
                        timeout=self.timeout
                    )
                    tsr_token = stamper(digest=hash_bytes)
                    # 成功后更新当前提供商信息
                    if provider_key is not None:
                        self.provider_name = provider_name
                        self.provider_key = provider_key
                        self.url = url
                        self.stamper = stamper
                    return tsr_token
                except Exception as e:
                    last_error = e
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)

        raise Exception(
            f"所有 TSA 提供商均失败 (尝试: {', '.join(p or 'custom' for p in providers_to_try)}): {last_error}"
        )

    def timestamp_data(self, data: bytes) -> bytes:
        """
        对原始数据生成时间戳

        Args:
            data: 要加时间戳的数据（二进制）

        Returns:
            TSR (Time-Stamp Response) 二进制令牌

        Raises:
            Exception: 时间戳请求失败
        """
        try:
            # 计算数据的哈希值
            hash_obj = hashlib.new(self.hashname)
            hash_obj.update(data)
            data_hash = hash_obj.digest()

            # 调用 TSA 服务获取时间戳（带重试和故障转移）
            tsr_token = self._call_with_retry(data_hash)

            return tsr_token
        except Exception as e:
            raise Exception(f"时间戳请求失败: {str(e)}")

    def timestamp_file(self, file_path: Path, output_path: Optional[Path] = None) -> Dict:
        """
        为文件生成时间戳（流式处理，不将整个文件载入内存）

        Args:
            file_path: 要加时间戳的文件路径
            output_path: TSR 文件输出路径（可选，默认为 file_path.tsr）

        Returns:
            包含时间戳信息的字典
        """
        file_path = Path(file_path)

        if not file_path.exists():
            return {
                'success': False,
                'message': f"文件不存在: {file_path}"
            }

        try:
            # 流式计算文件哈希（8KB 分块，避免大文件内存溢出）
            hash_obj = hashlib.new(self.hashname)
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    hash_obj.update(chunk)

            file_hash = hash_obj.hexdigest()

            # 确定输出路径
            if output_path is None:
                output_path = file_path.parent / f"{file_path.stem}.tsr"
            else:
                output_path = Path(output_path)

            # 委托给 timestamp_hash（处理 TSA 调用、重试和文件写入）
            result = self.timestamp_hash(file_hash, output_path)

            # 确保返回文件哈希
            if result.get('success'):
                result['hash'] = file_hash

            return result

        except Exception as e:
            return {
                'success': False,
                'message': f"时间戳生成失败: {str(e)}"
            }

    def timestamp_hash(self, hash_value: str, output_path: Path) -> Dict:
        """
        为已知的哈希值生成时间戳（用于 Merkle Root 等场景）

        Args:
            hash_value: 十六进制哈希值字符串
            output_path: TSR 文件输出路径

        Returns:
            包含时间戳信息的字典
        """
        try:
            # 将十六进制哈希值转换为二进制
            hash_bytes = bytes.fromhex(hash_value)

            # 获取时间戳令牌（带重试和故障转移）
            tsr_token = self._call_with_retry(hash_bytes)

            # 保存 TSR 文件
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(tsr_token)

            # 从 TSR 令牌中提取 TSA 认证时间（而非本机时钟）
            tsa_timestamp = datetime.now().isoformat()  # fallback
            tsa_issuer = self.provider_name
            try:
                from asn1crypto import tsp, cms
                # Try TimeStampResp first, then ContentInfo
                signed_data = None
                try:
                    ts_resp = tsp.TimeStampResp.load(tsr_token)
                    signed_data = ts_resp['time_stamp_token']['content']
                except (ValueError, KeyError, TypeError):
                    try:
                        ci = cms.ContentInfo.load(tsr_token)
                        if ci['content_type'].native == 'signed_data':
                            signed_data = ci['content']
                    except (ValueError, KeyError, TypeError):
                        pass

                if signed_data:
                    tst_info = signed_data['encap_content_info']['content'].parsed
                    gen_time = tst_info['gen_time'].native
                    if gen_time:
                        tsa_timestamp = gen_time.isoformat()

                    # Extract issuer CN from signer info
                    try:
                        signer_infos = signed_data['signer_infos']
                        if signer_infos:
                            sid = signer_infos[0]['sid']
                            if sid.name == 'issuer_and_serial_number':
                                for rdn in sid.chosen['issuer'].chosen:
                                    for attr in rdn:
                                        if attr['type'].dotted == '2.5.4.3':
                                            tsa_issuer = attr['value'].native
                                            break
                    except (KeyError, IndexError, ValueError):
                        pass
            except ImportError:
                pass  # asn1crypto not available, use fallback values

            return {
                'success': True,
                'timestamp': tsa_timestamp,
                'hash': hash_value,
                'issuer': tsa_issuer,
                'tsr_path': str(output_path),
                'algorithm': self.hashname.upper(),
                'message': f"时间戳生成成功，TSR 文件: {output_path.name}"
            }

        except Exception as e:
            return {
                'success': False,
                'message': f"时间戳生成失败: {str(e)}"
            }

    def verify_tsr(
        self,
        tsr_path: Path,
        data: Optional[bytes] = None,
        digest: Optional[bytes] = None,
    ) -> Dict:
        """
        验证 TSR 时间戳令牌

        Args:
            tsr_path: TSR 文件路径
            data: 原始数据（可选，库内部计算哈希后比对）
            digest: 预计算的哈希值（可选，直接与 TSR 中记录的哈希比对）
                    data 和 digest 二选一；都不传则仅验证 TSR 结构

        Returns:
            验证结果字典，包含 'valid', 'message', 'issuer' 等字段。
            当 data/digest 未提供时，结果包含 'partial_verification': True 标志。
        """
        tsr_path = Path(tsr_path)

        if not tsr_path.exists():
            return {
                'valid': False,
                'message': f"TSR 文件不存在: {tsr_path}"
            }

        try:
            with open(tsr_path, 'rb') as f:
                tsr_token = f.read()

            if digest is not None:
                # 直接用预计算的哈希比对（用于 Merkle Root 等场景）
                verified = rfc3161ng.check_timestamp(tsr_token, digest=digest)
                if verified:
                    return {
                        'valid': True,
                        'message': '时间戳验证通过（数据完整性已确认）',
                        'issuer': self._extract_issuer_from_tsr(tsr_token),
                    }
                else:
                    return {
                        'valid': False,
                        'message': '时间戳验证失败：哈希值不匹配'
                    }
            elif data is not None:
                # 传入原始数据，由库内部计算哈希后比对
                verified = rfc3161ng.check_timestamp(tsr_token, data=data)
                if verified:
                    return {
                        'valid': True,
                        'message': '时间戳验证通过（数据完整性已确认）',
                        'issuer': self._extract_issuer_from_tsr(tsr_token),
                    }
                else:
                    return {
                        'valid': False,
                        'message': '时间戳验证失败：哈希值不匹配'
                    }
            else:
                # 结构验证：无原始数据时，验证 TSR 文件结构有效性
                return self._verify_tsr_structure(tsr_token)

        except Exception as e:
            return {
                'valid': False,
                'message': f'时间戳验证失败: {str(e)}'
            }

    def _extract_issuer_from_tsr(self, tsr_token: bytes) -> str:
        """Extract the actual issuer CN from a TSR token using asn1crypto.

        Falls back to self.provider_name if parsing fails or asn1crypto
        is unavailable.  This ensures verify_tsr() reports the real issuer
        even after failover to a different TSA provider.
        """
        try:
            from asn1crypto import tsp, cms

            signed_data = None
            try:
                ts_resp = tsp.TimeStampResp.load(tsr_token)
                signed_data = ts_resp['time_stamp_token']['content']
            except (ValueError, KeyError, TypeError):
                try:
                    ci = cms.ContentInfo.load(tsr_token)
                    if ci['content_type'].native == 'signed_data':
                        signed_data = ci['content']
                except (ValueError, KeyError, TypeError):
                    pass

            if signed_data:
                signer_infos = signed_data['signer_infos']
                if signer_infos:
                    sid = signer_infos[0]['sid']
                    if sid.name == 'issuer_and_serial_number':
                        for rdn in sid.chosen['issuer'].chosen:
                            for attr in rdn:
                                if attr['type'].dotted == '2.5.4.3':  # CN
                                    return attr['value'].native
        except (ImportError, Exception):
            pass

        return self.provider_name

    def _verify_tsr_structure(self, tsr_token: bytes) -> Dict:
        """验证 TSR 令牌的 ASN.1 结构（不验证数据完整性）"""
        if len(tsr_token) < 20:
            return {'valid': False, 'message': 'TSR 文件过小，可能已损坏'}

        if tsr_token[0] != 0x30:
            return {'valid': False, 'message': 'TSR 文件不是有效的 ASN.1 DER 格式'}

        # 尝试 asn1crypto 深度结构验证
        try:
            from asn1crypto import tsp, cms

            # 格式 1: TimeStampResp
            try:
                ts_resp = tsp.TimeStampResp.load(tsr_token)
                status = ts_resp['status']['status'].native
                if status not in ('granted', 'granted_with_mods'):
                    return {
                        'valid': False,
                        'message': f'TSR 状态异常: {status}'
                    }
                return {
                    'valid': True,
                    'message': '时间戳结构验证通过（未验证数据完整性）',
                    'issuer': self.provider_name,
                    'partial_verification': True
                }
            except (ValueError, KeyError, TypeError):
                pass

            # 格式 2: ContentInfo/SignedData (DigiCert 等)
            try:
                content_info = cms.ContentInfo.load(tsr_token)
                if content_info['content_type'].native == 'signed_data':
                    return {
                        'valid': True,
                        'message': '时间戳结构验证通过（未验证数据完整性）',
                        'issuer': self.provider_name,
                        'partial_verification': True
                    }
            except (ValueError, KeyError, TypeError):
                pass

            return {'valid': False, 'message': '无法解析 TSR 结构'}

        except ImportError:
            # asn1crypto 不可用，基础结构检查已通过（size + 0x30 tag）
            return {
                'valid': True,
                'message': '时间戳基础结构检查通过（安装 asn1crypto 可获得深度验证）',
                'issuer': self.provider_name,
                'partial_verification': True
            }

    @classmethod
    def get_provider_info(cls, provider: str) -> Optional[Dict]:
        """获取预定义服务提供商的信息"""
        return cls.PROVIDERS.get(provider)

    @classmethod
    def list_providers(cls) -> Dict[str, Dict]:
        """列出所有预定义的服务提供商"""
        return cls.PROVIDERS.copy()
