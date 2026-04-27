"""
tshark_runner.py - TShark 子进程封装
职责:
  - 构建 TShark 命令行
  - 执行子进程并处理超时/错误
  - 返回标准输出文本
"""

import logging
import subprocess
import sys
from typing import List, Optional

logger = logging.getLogger(__name__)


class TsharkRunner:
    """TShark 子进程运行器"""

    def __init__(self, tshark_path: str, timeout: int = 0):
        """
        Args:
            tshark_path: tshark 可执行文件路径
            timeout: 单次运行超时秒数, 0=不限制
        """
        self.tshark_path = tshark_path
        self.timeout = timeout or None  # None = 无限

    def run(self, args: List[str], pcap_path: str) -> str:
        """
        执行 tshark -r <pcap> [args ...] 并返回 stdout

        Args:
            args: TShark 额外参数列表
            pcap_path: 输入 pcap 文件路径

        Returns:
            TShark 标准输出文本

        Raises:
            RuntimeError: tshark 非零退出或超时
        """
        cmd = [self.tshark_path, "-r", pcap_path] + args
        logger.debug("执行: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"TShark 执行超时 ({self.timeout}s): {' '.join(cmd)}"
            )
        except FileNotFoundError:
            raise RuntimeError(f"TShark 未找到: {self.tshark_path}")

        if result.returncode != 0:
            stderr = result.stderr.strip()
            logger.warning("TShark 退出码 %d: %s", result.returncode, stderr)

        return result.stdout

    # ─── 高级封装 ───

    def summary(self, pcap_path: str) -> str:
        """捕获文件概要"""
        return self.run(["-q", "-z", "io,stat,0"], pcap_path)

    def conv_tcp(self, pcap_path: str) -> str:
        """TCP 会话统计"""
        return self.run(["-q", "-z", "conv,tcp"], pcap_path)

    def conv_udp(self, pcap_path: str) -> str:
        """UDP 会话统计"""
        return self.run(["-q", "-z", "conv,udp"], pcap_path)

    def endpoints_ip(self, pcap_path: str) -> str:
        """IP 端点统计"""
        return self.run(["-q", "-z", "endpoints,ip"], pcap_path)

    def protocols(self, pcap_path: str) -> str:
        """协议分层统计"""
        return self.run(["-q", "-z", "io,phs"], pcap_path)

    def expert_info(self, pcap_path: str) -> str:
        """专家信息"""
        return self.run(["-q", "-z", "expert"], pcap_path)

    def display_filter(self, pcap_path: str, filter_str: str, extra_args: Optional[List[str]] = None) -> str:
        """使用显示过滤器提取数据"""
        args = ["-Y", filter_str]
        if extra_args:
            args.extend(extra_args)
        return self.run(args, pcap_path)

    def export_objects(self, pcap_path: str, protocol: str, output_dir: str) -> str:
        """导出对象 (如 HTTP/SMB 文件)"""
        return self.run(
            ["--export-objects", f"{protocol},{output_dir}"],
            pcap_path,
        )

    def time_format(self, pcap_path: str) -> str:
        """获取首尾包时间戳"""
        return self.run(
            ["-Y", "frame", "-T", "fields",
             "-e", "frame.time",
             "-e", "frame.time_delta"],
            pcap_path,
        )

    def dns_queries(self, pcap_path: str) -> str:
        """DNS 查询"""
        return self.run(
            ["-Y", "dns.qry.name", "-T", "fields",
             "-e", "dns.qry.name",
             "-e", "dns.resp.addr"],
            pcap_path,
        )

    def http_requests(self, pcap_path: str) -> str:
        """HTTP 请求概览"""
        return self.run(
            ["-Y", "http.request", "-T", "fields",
             "-e", "frame.number",
             "-e", "ip.src",
             "-e", "ip.dst",
             "-e", "http.request.method",
             "-e", "http.host",
             "-e", "http.request.uri",
             "-e", "http.response.code"],
            pcap_path,
        )

    def tcp_streams(self, pcap_path: str, stream_indices: List[int]) -> str:
        """提取指定 TCP 流的原始数据"""
        parts = []
        for idx in stream_indices:
            data = self.run(
                ["-q", "-z", f"follow,tcp,ascii,{idx}"],
                pcap_path,
            )
            parts.append(data)
        return "\n---STREAM-SEPARATOR---\n".join(parts)

    def extract_stream_pcap(self, pcap_path: str, stream_index: int,
                            output_path: str) -> str:
        """提取单个 TCP 流到独立 pcap"""
        return self.run(
            ["-Y", f"tcp.stream=={stream_index}",
             "-w", output_path],
            pcap_path,
        )
