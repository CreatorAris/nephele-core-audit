"""
Nephele Workshop - 数字存证工具类
Merkle Tree 算法实现，用于批量文件哈希聚合

Developer: ArisFusion Studio
"""

import hashlib
from typing import List, Dict, Optional
from pathlib import Path


class MerkleTree:
    """
    Merkle Tree 实现，用于将多个文件的哈希值聚合成单个根哈希

    优势：
    - 支持 100+ 文件批量处理
    - 单个根哈希可代表整个批次
    - 节省 TSA 调用成本（1 次调用 vs N 次调用）

    Known limitation (second-preimage resistance):
        This implementation does NOT use domain separation prefixes for leaf vs
        internal nodes (i.e. b'\\x00' for leaves, b'\\x01' for internal nodes as
        recommended by RFC 6962 §2.1).  Adding prefixes would change the root hash
        computation and break backward compatibility with all existing .nep files
        and the verification website (verify.arisfusion.com).  A future tree_version
        bump can introduce domain separation; the current version is safe for our
        threat model (user-submitted files, not adversarial tree construction).
    """
    
    def __init__(self, hash_algorithm: str = 'sha256'):
        """
        初始化 Merkle Tree
        
        Args:
            hash_algorithm: 哈希算法，默认 'sha256'
        """
        self.hash_algorithm = hash_algorithm
        self.leaves: List[str] = []
        self.tree: List[List[str]] = []
        self.root_hash: Optional[str] = None
    
    def add_leaf(self, data: bytes) -> str:
        """
        添加叶子节点（文件哈希）
        
        Args:
            data: 文件数据或哈希值（bytes）
        
        Returns:
            叶子节点的哈希值
        """
        hash_obj = hashlib.new(self.hash_algorithm)
        hash_obj.update(data)
        leaf_hash = hash_obj.hexdigest()
        self.leaves.append(leaf_hash)
        return leaf_hash
    
    def add_file_hash(self, file_hash: str) -> None:
        """
        直接添加文件哈希值（已计算好的）
        
        Args:
            file_hash: 文件的十六进制哈希值
        """
        self.leaves.append(file_hash)
    
    def build(self) -> str:
        """
        构建 Merkle Tree 并返回根哈希
        
        Returns:
            根哈希值（十六进制字符串）
        """
        if not self.leaves:
            raise ValueError("Merkle Tree 没有叶子节点")
        
        # 如果只有一个叶子节点，直接返回
        if len(self.leaves) == 1:
            self.root_hash = self.leaves[0]
            return self.root_hash
        
        # 构建树：从叶子节点开始，逐层向上
        current_level = self.leaves.copy()
        self.tree = [current_level]
        
        while len(current_level) > 1:
            next_level = []
            
            # 成对处理节点
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    # 两个节点：合并哈希
                    combined = current_level[i] + current_level[i + 1]
                else:
                    # 奇数个节点：最后一个节点复制后与自己合并
                    combined = current_level[i] + current_level[i]
                
                # 计算父节点哈希
                hash_obj = hashlib.new(self.hash_algorithm)
                hash_obj.update(combined.encode('utf-8'))
                parent_hash = hash_obj.hexdigest()
                next_level.append(parent_hash)
            
            self.tree.append(next_level)
            current_level = next_level
        
        # 根哈希是最后一层的唯一节点
        self.root_hash = current_level[0]
        return self.root_hash
    
    def get_proof(self, leaf_index: int) -> List[Dict]:
        """
        获取指定叶子节点的 Merkle Proof（用于验证）

        Args:
            leaf_index: 叶子节点索引

        Returns:
            Merkle Proof 路径，每个元素为 {'hash': str, 'position': 'left'|'right'}
            position 表示兄弟节点在合并时的位置
        """
        if not self.tree:
            self.build()

        if leaf_index >= len(self.leaves):
            raise IndexError(f"叶子节点索引超出范围: {leaf_index}")

        proof = []
        current_index = leaf_index
        current_level = 0

        while current_level < len(self.tree) - 1:
            level = self.tree[current_level]

            # 找到兄弟节点并记录位置
            if current_index % 2 == 0:
                # 当前是左节点，兄弟在右侧
                sibling_index = current_index + 1
                if sibling_index < len(level):
                    proof.append({'hash': level[sibling_index], 'position': 'right'})
                else:
                    # 奇数情况，兄弟是自己（已复制）
                    proof.append({'hash': level[current_index], 'position': 'right'})
            else:
                # 当前是右节点，兄弟在左侧
                sibling_index = current_index - 1
                proof.append({'hash': level[sibling_index], 'position': 'left'})

            # 移动到上一层
            current_index = current_index // 2
            current_level += 1

        return proof

    def verify_proof(self, leaf_hash: str, proof: List[Dict], root_hash: str) -> bool:
        """
        验证 Merkle Proof

        Args:
            leaf_hash: 叶子节点哈希
            proof: Merkle Proof 路径（由 get_proof 返回）
            root_hash: 根哈希

        Returns:
            验证是否通过
        """
        current_hash = leaf_hash

        for step in proof:
            sibling_hash = step['hash']
            position = step['position']

            # 按照 build() 相同的位置顺序合并：左 + 右
            if position == 'right':
                combined = current_hash + sibling_hash
            else:
                combined = sibling_hash + current_hash

            hash_obj = hashlib.new(self.hash_algorithm)
            hash_obj.update(combined.encode('utf-8'))
            current_hash = hash_obj.hexdigest()

        return current_hash == root_hash
    
    def get_tree_structure(self) -> Dict:
        """
        获取树结构信息（用于调试和验证）
        
        Returns:
            包含树结构的字典
        """
        return {
            'algorithm': self.hash_algorithm,
            'leaf_count': len(self.leaves),
            'root_hash': self.root_hash,
            'tree_levels': len(self.tree),
            'leaves': self.leaves,
            'tree': self.tree
        }


def build_merkle_tree_from_files(
    file_paths: List[Path],
    progress_callback=None,
) -> MerkleTree:
    """
    从文件列表构建 Merkle Tree（便捷函数）

    Args:
        file_paths: 文件路径列表
        progress_callback: 可选进度回调函数 (current, total)

    Returns:
        构建好的 MerkleTree 对象。
        tree.file_hashes 是 {str(path): hex_hash} 字典，可直接复用于 manifest。
    """
    tree = MerkleTree()
    tree.file_hashes = {}  # path → hash, populated during build
    total = len(file_paths)

    for i, file_path in enumerate(file_paths):
        if not file_path.exists():
            continue

        hash_obj = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)

        file_hash = hash_obj.hexdigest()
        tree.add_file_hash(file_hash)
        tree.file_hashes[str(file_path)] = file_hash

        if progress_callback:
            progress_callback(i + 1, total)

    tree.build()
    return tree
