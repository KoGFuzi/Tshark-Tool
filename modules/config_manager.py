"""
config_manager.py - 配置管理 & 命令行参数解析
职责:
  1. 从 config.yaml 加载配置
  2. 用 argparse 解析命令行参数
  3. 合并两者 + 自动检测 TShark 路径
  4. 创建输出目录
"""

import argparse
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Optional

from .parsers import load_yaml

logger = logging.getLogger(__name__)

# ─── 默认配置 ───
_DEFAULTS = {
    "tshark_path": "",
    "output_dir": "",
    "log_level": "INFO",
    "timeout": 0,
    "risk_level": 1,
    "split_size_mb": 10,
}

# ─── TShark 自动检测顺序 ───
_TSHARK_CANDIDATES_WIN = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]
_TSHARK_CANDIDATES_LINUX = [
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
    "/usr/sbin/tshark",
]


def _detect_tshark() -> Optional[str]:
    """在系统 PATH 和常见路径中查找 tshark"""
    found = shutil.which("tshark")
    if found:
        return found

    candidates = (
        _TSHARK_CANDIDATES_WIN if sys.platform == "win32"
        else _TSHARK_CANDIDATES_LINUX
    )
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


def parse_args(argv=None) -> argparse.Namespace:
    """命令行参数解析"""
    ap = argparse.ArgumentParser(
        prog="pcap_analyzer",
        description="基于 TShark 的 PCAP 流量分析工具 (跨平台)",
    )
    ap.add_argument("pcap", help="待分析的 pcap/pcapng 文件路径")
    ap.add_argument(
        "-r", "--risk",
        type=int,
        choices=[1, 2, 3],
        default=None,
        help="分析风险等级 (1=基础, 2=进阶, 3=深度), 覆盖配置文件",
    )
    ap.add_argument(
        "-o", "--output",
        default=None,
        help="输出目录, 覆盖配置文件",
    )
    ap.add_argument(
        "-t", "--tshark",
        default=None,
        help="TShark 可执行文件路径, 覆盖配置文件",
    )
    ap.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="TShark 单次运行超时秒数",
    )
    ap.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="启用详细日志 (DEBUG)",
    )
    ap.add_argument(
        "-m", "--model",
        nargs="*",
        default=None,
        choices=["sql", "ftp", "icmp", "httpd", "extra"],
        help="分析模式 (risk≥2 时有效): sql / ftp / icmp / httpd / extra, 可多选, 留空则运行全部",
    )
    ap.add_argument(
        "-c", "--config",
        default=None,
        help="指定配置文件路径 (默认同目录 config.yaml)",
    )
    return ap.parse_args(argv)


class ConfigManager:
    """
    统一配置对象:
      - 优先级: 命令行 > 配置文件 > 默认值
      - 自动检测 TShark
      - 创建输出目录
    """

    def __init__(self, argv=None):
        args = parse_args(argv)

        # 1) 加载配置文件
        config_path = args.config
        if config_path is None:
            config_path = str(
                Path(__file__).resolve().parent.parent / "config.yaml"
            )
        self._yaml = load_yaml(config_path) if os.path.isfile(config_path) else {}

        # 2) 合并配置
        self.risk_level: int = args.risk or self._yaml.get("risk_level", _DEFAULTS["risk_level"])
        self.timeout: int = args.timeout if args.timeout is not None else self._yaml.get("timeout", _DEFAULTS["timeout"])
        self.split_size_mb: int = self._yaml.get("split_size_mb", _DEFAULTS["split_size_mb"])

        # 日志
        if args.verbose:
            self.log_level = "DEBUG"
        else:
            self.log_level = self._yaml.get("log_level", _DEFAULTS["log_level"])

        # TShark
        self.tshark_path: str = args.tshark or self._yaml.get("tshark_path", "") or _detect_tshark() or ""
        if not self.tshark_path:
            logger.error("未找到 TShark, 请通过 -t 参数或 config.yaml 指定路径")
            sys.exit(1)

        # 输出目录
        pcap_path = Path(args.pcap).resolve()
        self.pcap_path: str = str(pcap_path)
        if not pcap_path.is_file():
            logger.error("PCAP 文件不存在: %s", self.pcap_path)
            sys.exit(1)

        raw_output = args.output or self._yaml.get("output_dir", "")
        if raw_output:
            self.output_dir: str = str(Path(raw_output).resolve())
        else:
            self.output_dir = str(pcap_path.parent / "output")

        os.makedirs(self.output_dir, exist_ok=True)

        # 子配置
        self.model: list = args.model if args.model is not None else self._yaml.get("model", [])
        # risk<2 时忽略 model
        if self.risk_level < 2 and self.model:
            logger.warning("risk<2 时 --model 参数无效, 已忽略")
            self.model = []
        self.file_extraction = self._yaml.get("file_extraction", {})
        self.sql_injection_patterns = self._yaml.get("sql_injection_patterns", [])
        self.icmp_anomaly = self._yaml.get("icmp_anomaly", {})
        self.httpd_analysis = self._yaml.get("httpd_analysis", {})

        logger.info("配置加载完成 — risk=%d, tshark=%s, output=%s",
                     self.risk_level, self.tshark_path, self.output_dir)

    # ─── 便捷属性 ───
    @property
    def pcap_name(self) -> str:
        return Path(self.pcap_path).stem

    @property
    def pcap_dir(self) -> str:
        return str(Path(self.pcap_path).parent)
