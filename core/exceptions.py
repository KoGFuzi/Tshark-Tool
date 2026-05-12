"""
Tshark-tool exception hierarchy.

All custom exceptions inherit from TsharkToolError, providing a single
catch-point at the CLI boundary while enabling granular handling internally.
"""


class TsharkToolError(Exception):
    """Base exception for all tshark-tool errors."""
    pass


class TsharkNotFoundError(TsharkToolError):
    """TShark executable not found in PATH."""
    def __init__(self):
        super().__init__(
            "tshark not found. Install Wireshark/TShark and ensure it's in PATH."
        )


class TsharkExecutionError(TsharkToolError):
    """TShark subprocess returned a non-zero exit code."""
    def __init__(self, returncode: int, stderr: str, stdout: str = ""):
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout
        super().__init__(
            f"tshark error (rc={returncode}): {stderr.strip() or stdout[:200]}"
        )


class PcapNotFoundError(TsharkToolError):
    """Specified pcap file does not exist."""
    def __init__(self, path: str):
        self.path = path
        super().__init__(f"File not found: {path}")


class HexDecodeError(TsharkToolError):
    """Invalid or malformed hex input."""
    pass


class Base64DecodeError(TsharkToolError):
    """Invalid or malformed base64 input."""
    pass


class ZipError(TsharkToolError):
    """ZIP-related operation failure."""
    pass


class PasswordNotFoundError(ZipError):
    """Password cracking exhausted without finding a valid password."""
    pass


class NoDataFoundError(TsharkToolError):
    """No matching data found in pcap."""
    pass
