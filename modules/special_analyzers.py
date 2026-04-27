"""
special_analyzers.py - 进阶/深度分析模块 (risk=2,3)
职责:
  - SqlAnalyzer   : SQL 注入检测
  - FtpAnalyzer   : FTP 明文凭据提取
  - ICMPAnalyzer  : ICMP 异常检测 (大包/高频)
  - HttpdAnalyzer : HTTP 流量深度分析
  - ExtraFileExtractor : 额外文件提取 (图片/文档/压缩包等)
  - 工厂函数 create_special_analyzer()
"""

import abc
import csv
import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

from .tshark_runner import TsharkRunner

logger = logging.getLogger(__name__)


# ═════════════════════════════════════════════════════════════
#  抽象基类
# ═════════════════════════════════════════════════════════════

class SpecialAnalyzer(abc.ABC):
    """进阶分析器抽象基类"""

    name: str = "base"

    def __init__(self, runner: TsharkRunner, output_dir: str, config: dict = None):
        self.runner = runner
        self.output_dir = output_dir
        self.config = config or {}
        self.result_path: Optional[str] = None

    @abc.abstractmethod
    def analyze(self, pcap_path: str) -> str:
        """执行分析, 返回报告文件路径"""
        ...

    def _ensure_dir(self, subdir: str = "") -> str:
        dir_path = os.path.join(self.output_dir, subdir) if subdir else self.output_dir
        os.makedirs(dir_path, exist_ok=True)
        return dir_path

    def _write(self, filename: str, content: str, subdir: str = "special") -> str:
        dir_path = self._ensure_dir(subdir)
        path = os.path.join(dir_path, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info("  [%s] 写入 %s", self.name, path)
        return path


# ═════════════════════════════════════════════════════════════
#  SQL 注入检测
# ═════════════════════════════════════════════════════════════

class SqlAnalyzer(SpecialAnalyzer):
    name = "sql_injection"

    def __init__(self, runner: TsharkRunner, output_dir: str, config: dict = None):
        super().__init__(runner, output_dir, config)
        patterns = self.config.get("sql_injection_patterns", [])
        self._regexes = [re.compile(p) for p in patterns]

    def analyze(self, pcap_path: str) -> str:
        logger.info("  [sql] 检测 SQL 注入 ...")
        # 提取 HTTP 请求 URI 和 POST body
        raw = self.runner.display_filter(
            pcap_path,
            "http.request or http.file_data",
            ["-T", "fields",
             "-e", "frame.number",
             "-e", "ip.src",
             "-e", "ip.dst",
             "-e", "http.request.uri",
             "-e", "http.file_data",
             "-e", "urlencoded-form.key",
             "-e", "urlencoded-form.value"],
        )

        lines = ["=" * 60, "SQL 注入检测报告", "=" * 60, ""]
        found = 0

        for line in raw.strip().splitlines():
            if not line.strip():
                continue
            for regex in self._regexes:
                if regex.search(line):
                    lines.append(f"[!] 疑似注入  {line.strip()}")
                    lines.append(f"    匹配规则: {regex.pattern}")
                    lines.append("")
                    found += 1
                    break

        lines.insert(3, f"检测结果: 发现 {found} 条疑似 SQL 注入")
        lines.append("")

        if not self._regexes:
            lines.append("(未配置检测规则, 跳过检测)")

        self.result_path = self._write("sql_injection.txt", "\n".join(lines))
        return self.result_path


# ═════════════════════════════════════════════════════════════
#  FTP 明文凭据
# ═════════════════════════════════════════════════════════════

class FtpAnalyzer(SpecialAnalyzer):
    name = "ftp_cleartext"

    def analyze(self, pcap_path: str) -> str:
        logger.info("  [ftp] 提取 FTP 明文凭据 ...")
        raw = self.runner.display_filter(
            pcap_path,
            "ftp.request.command == USER or ftp.request.command == PASS",
            ["-T", "fields",
             "-e", "frame.number",
             "-e", "ip.src",
             "-e", "ip.dst",
             "-e", "ftp.request.command",
             "-e", "ftp.request.arg"],
        )

        lines = ["=" * 60, "FTP 明文凭据分析", "=" * 60, ""]
        creds = []

        for line in raw.strip().splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) >= 5:
                frame, src, dst, cmd, arg = parts[0], parts[1], parts[2], parts[3], parts[4]
                lines.append(f"帧 {frame}: {src} -> {dst}  {cmd} {arg}")
                creds.append((src, cmd, arg))

        lines.insert(3, f"共提取 {len(creds)} 条凭据记录")
        lines.append("")

        # CSV
        csv_path = os.path.join(self._ensure_dir("special"), "ftp_credentials.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["源IP", "命令", "参数"])
            writer.writerows(creds)

        self.result_path = self._write("ftp_cleartext.txt", "\n".join(lines))
        return self.result_path


# ═════════════════════════════════════════════════════════════
#  ICMP 异常检测
# ═════════════════════════════════════════════════════════════

class ICMPAnalyzer(SpecialAnalyzer):
    name = "icmp_anomaly"

    def __init__(self, runner: TsharkRunner, output_dir: str, config: dict = None):
        super().__init__(runner, output_dir, config)
        self.large_bytes = self.config.get("large_packet_bytes", 1000)
        self.high_freq = self.config.get("high_frequency_count", 100)

    def analyze(self, pcap_path: str) -> str:
        logger.info("  [icmp] 检测 ICMP 异常 ...")
        raw = self.runner.display_filter(
            pcap_path,
            "icmp",
            ["-T", "fields",
             "-e", "frame.number",
             "-e", "ip.src",
             "-e", "ip.dst",
             "-e", "frame.len",
             "-e", "icmp.type"],
        )

        lines = ["=" * 60, "ICMP 异常检测报告", "=" * 60, ""]

        large_packets = []
        src_counter: Dict[str, int] = {}

        for line in raw.strip().splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            frame, src, dst, length, icmp_type = parts
            try:
                pkt_len = int(length)
            except ValueError:
                continue

            src_counter[src] = src_counter.get(src, 0) + 1

            if pkt_len > self.large_bytes:
                large_packets.append((frame, src, dst, pkt_len, icmp_type))

        # 大包
        lines.append(f"--- 大包检测 (阈值 {self.large_bytes} 字节) ---")
        if large_packets:
            for frame, src, dst, length, itype in large_packets:
                lines.append(f"  帧 {frame}: {src} -> {dst}, 长度={length}B, type={itype}")
        else:
            lines.append("  未发现异常大包")
        lines.append("")

        # 高频
        lines.append(f"--- 高频检测 (阈值 {self.high_freq} 包) ---")
        high_freq_sources = {ip: c for ip, c in src_counter.items() if c >= self.high_freq}
        if high_freq_sources:
            for ip, count in sorted(high_freq_sources.items(), key=lambda x: -x[1]):
                lines.append(f"  {ip}: {count} 个 ICMP 包")
        else:
            lines.append("  未发现高频源")
        lines.append("")

        self.result_path = self._write("icmp_anomaly.txt", "\n".join(lines))
        return self.result_path


# ═════════════════════════════════════════════════════════════
#  HTTP 流量深度分析
# ═════════════════════════════════════════════════════════════

class HttpdAnalyzer(SpecialAnalyzer):
    name = "httpd"

    def analyze(self, pcap_path: str) -> str:
        logger.info("  [httpd] HTTP 流量深度分析 ...")

        focus_codes = set(str(c) for c in self.config.get("status_codes", []))
        focus_methods = set(self.config.get("methods", ["GET", "POST"]))

        raw = self.runner.http_requests(pcap_path)
        resp_raw = self.runner.display_filter(
            pcap_path,
            "http.response",
            ["-T", "fields",
             "-e", "frame.number",
             "-e", "ip.src",
             "-e", "ip.dst",
             "-e", "http.response.code",
             "-e", "http.content_type",
             "-e", "http.server"],
        )

        lines = ["=" * 60, "HTTP 流量深度分析", "=" * 60, ""]

        # 请求统计
        req_lines = [l for l in raw.strip().splitlines() if l.strip()]
        method_counter: Dict[str, int] = {}
        suspicious = []

        for line in req_lines:
            parts = line.split("\t")
            if len(parts) >= 5:
                method = parts[3]
                method_counter[method] = method_counter.get(method, 0) + 1

                # 检查可疑方法
                if method in ("PUT", "DELETE", "OPTIONS"):
                    suspicious.append(
                        f"  帧 {parts[0]}: {parts[1]} -> {parts[2]} {method} {parts[4]}"
                    )

        lines.append("--- 请求方法统计 ---")
        for method, count in sorted(method_counter.items(), key=lambda x: -x[1]):
            lines.append(f"  {method}: {count}")
        lines.append("")

        # 响应统计
        resp_lines = [l for l in resp_raw.strip().splitlines() if l.strip()]
        code_counter: Dict[str, int] = {}

        for line in resp_lines:
            parts = line.split("\t")
            if len(parts) >= 4:
                code = parts[3]
                code_counter[code] = code_counter.get(code, 0) + 1

        lines.append("--- 响应状态码统计 ---")
        for code, count in sorted(code_counter.items()):
            marker = " [关注]" if code in focus_codes else ""
            lines.append(f"  {code}: {count}{marker}")
        lines.append("")

        # 可疑方法
        lines.append("--- 可疑 HTTP 方法 ---")
        if suspicious:
            lines.extend(suspicious)
        else:
            lines.append("  未发现 PUT/DELETE/OPTIONS 请求")
        lines.append("")

        # CSV
        csv_path = os.path.join(self._ensure_dir("special"), "http_requests.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["帧号", "源IP", "目的IP", "方法", "Host", "URI"])
            for line in req_lines:
                parts = line.split("\t")
                if len(parts) >= 6:
                    writer.writerow(parts[:6])

        self.result_path = self._write("httpd_analysis.txt", "\n".join(lines))
        return self.result_path


# ═════════════════════════════════════════════════════════════
#  额外文件提取
# ═════════════════════════════════════════════════════════════

class ExtraFileExtractor(SpecialAnalyzer):
    name = "file_extraction"

    def __init__(self, runner: TsharkRunner, output_dir: str, config: dict = None):
        super().__init__(runner, output_dir, config)
        self.extensions = set(self.config.get("extensions", []))
        self.max_size_mb = self.config.get("max_file_size_mb", 50)

    def analyze(self, pcap_path: str) -> str:
        logger.info("  [extract] 提取额外文件 ...")
        extract_dir = os.path.join(self.output_dir, "special", "extracted_files")
        os.makedirs(extract_dir, exist_ok=True)

        lines = ["=" * 60, "额外文件提取报告", "=" * 60, ""]
        extracted = []

        # 尝试 HTTP 对象导出
        for proto in ("http", "smb", "imf"):
            try:
                self.runner.export_objects(pcap_path, proto, extract_dir)
            except RuntimeError as e:
                logger.debug("  [extract] %s 导出跳过: %s", proto, e)
                continue

        # 遍历提取目录
        if os.path.isdir(extract_dir):
            for fname in os.listdir(extract_dir):
                fpath = os.path.join(extract_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                ext = Path(fname).suffix.lstrip(".").lower()
                size_mb = os.path.getsize(fpath) / (1024 * 1024)

                if self.extensions and ext not in self.extensions:
                    continue
                if size_mb > self.max_size_mb:
                    logger.debug("  [extract] %s 超过大小限制, 跳过", fname)
                    continue

                extracted.append((fname, f"{size_mb:.2f} MB", ext))

        if extracted:
            lines.append(f"提取到 {len(extracted)} 个文件:")
            lines.append("")
            for fname, size, ext in extracted:
                lines.append(f"  {fname}  ({size})")
        else:
            lines.append("未提取到目标类型文件")

        lines.append("")
        lines.append(f"提取目录: {extract_dir}")

        self.result_path = self._write("file_extraction.txt", "\n".join(lines))
        return self.result_path


# ═════════════════════════════════════════════════════════════
#  工厂函数
# ═════════════════════════════════════════════════════════════

_RISK2_ANALYZERS = [SqlAnalyzer, FtpAnalyzer, ICMPAnalyzer, HttpdAnalyzer]
_RISK3_ANALYZERS = _RISK2_ANALYZERS + [ExtraFileExtractor]

# model 名称 → 分析器类 映射
_MODEL_MAP = {
    "sql": SqlAnalyzer,
    "ftp": FtpAnalyzer,
    "icmp": ICMPAnalyzer,
    "httpd": HttpdAnalyzer,
    "extra": ExtraFileExtractor,
}


def _instantiate(cls, runner, output_dir, sql_patterns, icmp_config,
                 httpd_config, file_extraction_config):
    """根据类类型传入对应配置创建实例"""
    if cls is SqlAnalyzer:
        return cls(runner, output_dir, {"sql_injection_patterns": sql_patterns or []})
    elif cls is ICMPAnalyzer:
        return cls(runner, output_dir, icmp_config or {})
    elif cls is HttpdAnalyzer:
        return cls(runner, output_dir, httpd_config or {})
    elif cls is ExtraFileExtractor:
        return cls(runner, output_dir, file_extraction_config or {})
    else:
        return cls(runner, output_dir)


def create_special_analyzer(
    model: str,
    runner: TsharkRunner,
    output_dir: str,
    **kwargs,
) -> SpecialAnalyzer:
    """
    工厂函数: 根据 model 名称创建单个分析器实例

    model: sql / ftp / icmp / httpd / extra
    """
    cls = _MODEL_MAP.get(model)
    if cls is None:
        raise ValueError(f"未知分析模式: {model}, 可选: {list(_MODEL_MAP.keys())}")
    return _instantiate(
        cls, runner, output_dir,
        kwargs.get("sql_patterns"),
        kwargs.get("icmp_config"),
        kwargs.get("httpd_config"),
        kwargs.get("file_extraction_config"),
    )


def create_special_analyzers(
    risk_level: int,
    runner: TsharkRunner,
    output_dir: str,
    model: list = None,
    sql_patterns: list = None,
    icmp_config: dict = None,
    httpd_config: dict = None,
    file_extraction_config: dict = None,
) -> List[SpecialAnalyzer]:
    """
    根据 risk_level 和 model 创建分析器实例列表

    risk=1 → [] (无进阶分析)
    risk=2 → 默认 SQL+FTP+ICMP+Httpd, model 指定时仅创建指定模块
    risk=3 → risk=2 + ExtraFileExtractor (model 可限定子集)
    """
    if risk_level < 2:
        return []

    # 确定候选类列表
    base = _RISK3_ANALYZERS if risk_level >= 3 else _RISK2_ANALYZERS

    # 若指定了 model, 仅创建对应分析器
    if model:
        candidates = []
        for m in model:
            cls = _MODEL_MAP.get(m)
            if cls and cls in base:
                candidates.append(cls)
            elif cls:
                logger.warning("model '%s' 在 risk=%d 下不可用, 已跳过", m, risk_level)
        base = candidates

    return [
        _instantiate(cls, runner, output_dir,
                     sql_patterns, icmp_config, httpd_config, file_extraction_config)
        for cls in base
    ]
