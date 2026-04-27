"""
parsers.py - 正则与解析工具
提供会话 IP 提取、时间格式解析、TShark 输出解析等公共解析函数
"""

import re
from typing import Optional

# ─── 会话行正则 ───
# 匹配 tshark -z conv,tcp 输出行:
#   192.168.1.1:12345 <-> 10.0.0.1:80 ...
# 也兼容 IPv6
_SESSION_RE = re.compile(
    r"(\[[\da-fA-F:.]+\]|[\d.]+)"
    r":(\d+)\s*<->\s*"
    r"(\[[\da-fA-F:.]+\]|[\d.]+)"
    r":(\d+)"
)

# ─── IP 统计行正则 ───
# 匹配 tshark -z endpoints 输出行
_ENDPOINT_RE = re.compile(
    r"(\[[\da-fA-F:.]+\]|[\d.]+)\s+"
)

# ─── YAML 安全加载 ───
try:
    from yaml import CLoader as _Loader, load as _yaml_load
except ImportError:
    try:
        from yaml import Loader as _Loader, load as _yaml_load
    except ImportError:
        _Loader = None
        _yaml_load = None


def extract_session_pairs(text: str):
    """从 -z conv,tcp 输出中提取 (src, sport, dst, dport) 四元组列表"""
    return [
        (m.group(1), int(m.group(2)), m.group(3), int(m.group(4)))
        for m in _SESSION_RE.finditer(text)
    ]


def extract_endpoints(text: str):
    """从 -z endpoints 输出中提取 IP 地址列表(去重保序)"""
    seen = set()
    result = []
    for m in _ENDPOINT_RE.finditer(text):
        ip = m.group(1).strip("[]")
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def parse_duration_seconds(duration_str: str) -> Optional[float]:
    """
    解析 tshark 输出的时长字符串成秒数
    支持格式: '123.456', '1h23m45s', '1:23:45.678'
    """
    if not duration_str:
        return None
    duration_str = duration_str.strip()

    # 纯数字
    try:
        return float(duration_str)
    except ValueError:
        pass

    # HH:MM:SS[.fff]
    m = re.match(r"(\d+):(\d+):(\d+(?:\.\d+)?)", duration_str)
    if m:
        return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + float(m.group(3))

    # HHh MMm SSs
    m = re.match(
        r"(?:(\d+)h)?\s*(?:(\d+)m)?\s*(?:(\d+(?:\.\d+)?)s)?",
        duration_str,
    )
    if m and any(m.groups()):
        h = int(m.group(1) or 0)
        mn = int(m.group(2) or 0)
        s = float(m.group(3) or 0)
        return h * 3600 + mn * 60 + s

    return None


def load_yaml(path: str) -> dict:
    """安全加载 YAML 文件, 若 PyYAML 不可用则回退到简易解析"""
    if _yaml_load is not None:
        with open(path, "r", encoding="utf-8") as f:
            return _yaml_load(f, Loader=_Loader) or {}
    # 无 PyYAML 时返回空字典并提示
    import logging
    logging.getLogger(__name__).warning(
        "PyYAML 未安装, 无法加载 %s, 使用默认配置", path
    )
    return {}


def sanitize_filename(name: str) -> str:
    """将 IP 等字符串转换为安全文件名"""
    return re.sub(r"[^\w.\-]", "_", name)
