#!/usr/bin/env python3
"""
pcap_analyzer.py - 基于 TShark 的 PCAP 流量分析工具 (跨平台)

用法:
    python pcap_analyzer.py <pcap文件> [选项]

选项:
    -r, --risk     分析风险等级 (1=基础, 2=进阶, 3=深度)
    -o, --output   输出目录
    -t, --tshark   TShark 路径
    --timeout      超时秒数
    -v, --verbose  详细日志
    -c, --config   配置文件路径
"""

import logging
import sys

from modules.config_manager import ConfigManager
from modules.manager import PcapAnalysisManager


def setup_logging(level: str) -> None:
    """配置日志"""
    fmt = "%(asctime)s [%(levelname)-5s] %(name)s: %(message)s"
    datefmt = "%H:%M:%S"
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format=fmt,
        datefmt=datefmt,
    )


def main() -> int:
    config = ConfigManager()
    setup_logging(config.log_level)

    manager = PcapAnalysisManager(config)
    results = manager.run()

    print(f"\n分析完成, 共生成 {len(results)} 份报告")
    print(f"输出目录: {config.output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
