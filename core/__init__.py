"""
Tshark-tool core module.
Low-level tshark wrapper, general-purpose utilities, exceptions, and logging.
"""

from core.exceptions import (
    Base64DecodeError,
    HexDecodeError,
    NoDataFoundError,
    PasswordNotFoundError,
    PcapNotFoundError,
    TsharkExecutionError,
    TsharkNotFoundError,
    TsharkToolError,
    ZipError,
)
from core.logconfig import get_logger, setup_logging
from core.tshark_wrapper import (
    export_objects,
    extract_raw_field,
    filter_packets,
    follow_stream,
    get_pcap_info,
    list_protocols,
    parse_tshark_fields,
    tshark_version,
)
from core.utils import (
    brute_force_zip,
    brute_force_zip_wordlist,
    bytes_to_hex_dump,
    decode_base64,
    detect_file_type,
    hex_dump_to_bytes,
    is_hex,
    try_unzip,
)

__all__ = [
    # Exceptions
    "TsharkToolError",
    "TsharkNotFoundError",
    "TsharkExecutionError",
    "PcapNotFoundError",
    "HexDecodeError",
    "Base64DecodeError",
    "ZipError",
    "PasswordNotFoundError",
    "NoDataFoundError",
    # Logging
    "setup_logging",
    "get_logger",
    # Tshark wrapper
    "get_pcap_info",
    "list_protocols",
    "parse_tshark_fields",
    "tshark_version",
    "filter_packets",
    "follow_stream",
    "export_objects",
    "extract_raw_field",
    # Utils
    "hex_dump_to_bytes",
    "bytes_to_hex_dump",
    "is_hex",
    "detect_file_type",
    "decode_base64",
    "try_unzip",
    "brute_force_zip",
    "brute_force_zip_wordlist",
]
