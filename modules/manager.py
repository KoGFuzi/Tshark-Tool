"""
manager.py - 主控制器
职责:
  - 持有 ConfigManager / TsharkRunner / BasicAnalyzer
  - 根据 risk_level 调度分析流程
  - 汇总报告
  - 统一日志
"""

import logging
import os
import time
from typing import Dict, List, Optional

from .config_manager import ConfigManager
from .tshark_runner import TsharkRunner
from .basic_analyzer import BasicAnalyzer
from .special_analyzers import create_special_analyzers

logger = logging.getLogger("pcap_analyzer")


class PcapAnalysisManager:
    """PCAP 分析主控制器"""

    def __init__(self, config: ConfigManager):
        self.config = config
        self.runner = TsharkRunner(config.tshark_path, config.timeout)
        self.basic = BasicAnalyzer(
            self.runner, config.output_dir, config.split_size_mb
        )
        self._special = create_special_analyzers(
            risk_level=config.risk_level,
            runner=self.runner,
            output_dir=config.output_dir,
            model=config.model,
            sql_patterns=config.sql_injection_patterns,
            icmp_config=config.icmp_anomaly,
            httpd_config=config.httpd_analysis,
            file_extraction_config=config.file_extraction,
        )
        self._report_paths: Dict[str, str] = {}

    def run(self) -> Dict[str, str]:
        """执行全部分析, 返回 {分析名: 报告路径}"""
        start = time.time()
        logger.info("=" * 60)
        logger.info("PCAP 分析开始: %s", self.config.pcap_path)
        logger.info("风险等级: %d", self.config.risk_level)
        if self.config.model:
            logger.info("分析模式: %s", ", ".join(self.config.model))
        logger.info("输出目录: %s", self.config.output_dir)
        logger.info("=" * 60)

        # ─── 基础分析 (所有等级) ───
        try:
            basic_results = self.basic.run(self.config.pcap_path)
            self._report_paths.update(basic_results)
        except Exception:
            logger.exception("基础分析执行失败")

        # ─── 进阶/深度分析 (risk≥2) ───
        if self._special:
            logger.info("===== 进阶分析 (Risk≥2) =====")
            for analyzer in self._special:
                try:
                    path = analyzer.analyze(self.config.pcap_path)
                    self._report_paths[analyzer.name] = path
                except Exception:
                    logger.exception("%s 分析执行失败", analyzer.name)

        # ─── 最终汇总 ───
        elapsed = time.time() - start
        self._write_summary(elapsed)

        logger.info("=" * 60)
        logger.info("分析完成, 耗时 %.1f 秒", elapsed)
        logger.info("所有报告已保存至: %s", self.config.output_dir)
        logger.info("=" * 60)

        return self._report_paths

    def _write_summary(self, elapsed: float) -> None:
        """生成最终汇总报告"""
        lines = [
            "=" * 60,
            "PCAP 分析汇总报告",
            "=" * 60,
            "",
            f"源文件: {self.config.pcap_path}",
            f"风险等级: {self.config.risk_level}",
            f"耗时: {elapsed:.1f} 秒",
            "",
            "--- 生成的报告文件 ---",
            "",
        ]

        for name, path in self._report_paths.items():
            rel = os.path.relpath(path, self.config.output_dir)
            lines.append(f"  {name:30s}  {rel}")

        lines.append("")
        lines.append(f"输出目录: {self.config.output_dir}")

        summary_path = os.path.join(self.config.output_dir, "analysis_summary.txt")
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        self._report_paths["summary"] = summary_path
