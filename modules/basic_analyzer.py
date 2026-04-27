"""
basic_analyzer.py - 基础分析模块 (risk=1)
职责:
  1. 捕获概要 (文件信息/统计)
  2. 时间格式分析
  3. 会话分析 (TCP/UDP)
  4. IP 统计
  5. 按会话拆分 pcap
"""

import csv
import logging
import os
from pathlib import Path
from typing import Dict, List, Tuple

from .parsers import extract_session_pairs, extract_endpoints, sanitize_filename
from .tshark_runner import TsharkRunner

logger = logging.getLogger(__name__)


class BasicAnalyzer:
    """Risk=1 基础分析器"""

    def __init__(self, runner: TsharkRunner, output_dir: str,
                 split_size_mb: int = 10):
        self.runner = runner
        self.output_dir = output_dir
        self.split_size_mb = split_size_mb
        self.results: Dict[str, str] = {}

    # ─── 公开接口 ───

    def run(self, pcap_path: str) -> Dict[str, str]:
        """执行全部基础分析, 返回 {分析名: 输出文件路径}"""
        logger.info("===== 基础分析 (Risk=1) =====")

        self.results["summary"] = self._summary(pcap_path)
        self.results["protocols"] = self._protocols(pcap_path)
        self.results["time_format"] = self._time_format(pcap_path)
        self.results["tcp_sessions"] = self._tcp_sessions(pcap_path)
        self.results["udp_sessions"] = self._udp_sessions(pcap_path)
        self.results["ip_stats"] = self._ip_stats(pcap_path)
        self.results["expert_info"] = self._expert_info(pcap_path)
        self._split_by_session(pcap_path)

        return self.results

    # ─── 各分析步骤 ───

    def _write_report(self, name: str, content: str, subdir: str = "") -> str:
        """将内容写入报告文件, 返回文件路径"""
        dir_path = os.path.join(self.output_dir, subdir) if subdir else self.output_dir
        os.makedirs(dir_path, exist_ok=True)
        path = os.path.join(dir_path, f"{name}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info("  [%s] 写入 %s", name, path)
        return path

    def _summary(self, pcap_path: str) -> str:
        """捕获文件概要"""
        raw = self.runner.summary(pcap_path)
        return self._write_report("01_summary", raw, "basic")

    def _protocols(self, pcap_path: str) -> str:
        """协议分层统计"""
        raw = self.runner.protocols(pcap_path)
        return self._write_report("02_protocols", raw, "basic")

    def _time_format(self, pcap_path: str) -> str:
        """时间格式分析 - 提取首尾包时间"""
        raw = self.runner.time_format(pcap_path)
        lines = [l for l in raw.strip().splitlines() if l.strip()]

        analysis_lines = ["=" * 60, "时间格式分析", "=" * 60, ""]

        if lines:
            analysis_lines.append(f"首包时间: {lines[0].split(chr(9))[0] if chr(9) in lines[0] else lines[0]}")
            if len(lines) > 1:
                analysis_lines.append(f"末包时间: {lines[-1].split(chr(9))[0] if chr(9) in lines[-1] else lines[-1]}")
            analysis_lines.append(f"总包数: {len(lines)}")
        else:
            analysis_lines.append("无可解析的时间数据")

        analysis_lines.append("")
        analysis_lines.append("--- 原始输出 ---")
        analysis_lines.append(raw)

        return self._write_report("03_time_format", "\n".join(analysis_lines), "basic")

    def _tcp_sessions(self, pcap_path: str) -> str:
        """TCP 会话统计"""
        raw = self.runner.conv_tcp(pcap_path)

        # 解析会话对
        pairs = extract_session_pairs(raw)
        lines = ["=" * 60, "TCP 会话分析", "=" * 60, ""]
        lines.append(f"TCP 会话总数: {len(pairs)}")
        lines.append("")

        # CSV 结构化输出
        csv_path = os.path.join(self.output_dir, "basic", "tcp_sessions.csv")
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["源IP", "源端口", "目的IP", "目的端口"])
            for src, sport, dst, dport in pairs:
                writer.writerow([src, sport, dst, dport])

        lines.append(f"结构化 CSV 已写入: tcp_sessions.csv")
        lines.append("")
        lines.append("--- 原始输出 ---")
        lines.append(raw)

        self._session_pairs = pairs  # 供分包使用
        return self._write_report("04_tcp_sessions", "\n".join(lines), "basic")

    def _udp_sessions(self, pcap_path: str) -> str:
        """UDP 会话统计"""
        raw = self.runner.conv_udp(pcap_path)
        return self._write_report("05_udp_sessions", raw, "basic")

    def _ip_stats(self, pcap_path: str) -> str:
        """IP 统计"""
        raw = self.runner.endpoints_ip(pcap_path)
        endpoints = extract_endpoints(raw)

        lines = ["=" * 60, "IP 端点统计", "=" * 60, ""]
        lines.append(f"唯一 IP 数: {len(endpoints)}")
        lines.append("")

        for i, ip in enumerate(endpoints, 1):
            lines.append(f"  {i:4d}. {ip}")

        lines.append("")
        lines.append("--- 原始输出 ---")
        lines.append(raw)

        return self._write_report("06_ip_stats", "\n".join(lines), "basic")

    def _expert_info(self, pcap_path: str) -> str:
        """专家信息"""
        raw = self.runner.expert_info(pcap_path)
        return self._write_report("07_expert_info", raw, "basic")

    def _split_by_session(self, pcap_path: str) -> None:
        """按 TCP 会话拆分 pcap 文件"""
        if not hasattr(self, "_session_pairs"):
            return

        split_dir = os.path.join(self.output_dir, "basic", "split_pcaps")
        os.makedirs(split_dir, exist_ok=True)

        logger.info("  [split] 开始按会话拆分 pcap ...")
        for idx, (src, sport, dst, dport) in enumerate(self._session_pairs):
            fname = f"stream_{idx}_{sanitize_filename(src)}_{sport}_{sanitize_filename(dst)}_{dport}.pcap"
            out_path = os.path.join(split_dir, fname)
            try:
                self.runner.extract_stream_pcap(pcap_path, idx, out_path)
                logger.debug("  [split] %s", fname)
            except RuntimeError as e:
                logger.warning("  [split] 流 %d 提取失败: %s", idx, e)

        logger.info("  [split] 拆分完成, 保存至 %s", split_dir)
