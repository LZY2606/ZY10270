"""资源预算：阻止解压炸弹、伪造超大记录与候选风暴。

预算只做"接受/拒绝"判定，解析器不会为了打开文件而放宽任何限制。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Budget:
    max_file_size: int = 1024 * 1024 * 1024  # 1 GiB 原始字节
    max_entries: int = 100_000
    max_uncompressed_total: int = 2 * 1024 * 1024 * 1024  # 2 GiB 累计解压
    max_uncompressed_member: int = 512 * 1024 * 1024  # 512 MiB 单成员
    max_candidates: int = 1024
    max_comment_len: int = 65_535  # 格式上限，超出即伪造
    max_extra_total: int = 65_535  # 单头 extra 上限


DEFAULT_BUDGET = Budget()
