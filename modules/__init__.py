"""
Tshark-tool analysis modules.
Protocol-specific analyzers and file extraction.
"""

from modules.dns_analyzer import analyze_dns, extract_dns_data, summary as dns_summary
from modules.extractor import (
    extract_hex_from_filter,
    extract_zip_from_pcap,
    hex_to_file,
)
from modules.ftp_analyzer import analyze_ftp, extract_all_ftp_data, summary as ftp_summary
from modules.http_analyzer import (
    analyze_http,
    extract_post_data,
    extract_response_data,
    summary as http_summary,
)
from modules.udp_analyzer import (
    analyze_udp,
    extract_udp_streams,
    get_udp_streams,
    summary as udp_summary,
)

__all__ = [
    # DNS
    "analyze_dns",
    "dns_summary",
    "extract_dns_data",
    # FTP
    "analyze_ftp",
    "extract_all_ftp_data",
    "ftp_summary",
    # HTTP
    "analyze_http",
    "extract_post_data",
    "extract_response_data",
    "http_summary",
    # UDP
    "analyze_udp",
    "extract_udp_streams",
    "get_udp_streams",
    "udp_summary",
    # Extractor
    "extract_zip_from_pcap",
    "extract_hex_from_filter",
    "hex_to_file",
]
