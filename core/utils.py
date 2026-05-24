"""
Utility functions: hex decoding, base64, zip cracking, file type detection.

Pure-Python with no tshark dependency.  Requires pyzipper for AES zip support.
"""

import base64
import itertools
import string
import zipfile
import zlib
import pyzipper
from typing import Callable, Optional

from core.exceptions import Base64DecodeError, HexDecodeError


# ─── Hex ──────────────────────────────────────────────────────────


def is_hex(s: str) -> bool:
    """Check if a string is valid hexadecimal.

    Accepts both uppercase and lowercase hex digits.

    Args:
        s: String to check.

    Returns:
        True if s is a valid hex string (no prefix/suffix chars).
    """
    if not s or s[0] in "+-":
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def hex_dump_to_bytes(hex_str: str) -> bytes:
    """Convert a hex dump string to bytes.

    Handles various formats:
    - ``"504b0304"`` (continuous)
    - ``"50:4b:03:04"`` (colon-separated)
    - ``"50 4b 03 04"`` (space-separated)
    - Mixed with ASCII sidebar like Wireshark hex dump

    Args:
        hex_str: Hex dump string in any supported format.

    Returns:
        Decoded bytes.

    Raises:
        HexDecodeError: If no valid hex data found or odd length.
    """
    # Strip BOM and leading/trailing whitespace
    hex_str = hex_str.lstrip("\ufeff").strip()

    # Remove common separators for the quick check
    raw = hex_str.replace(":", "").replace("-", "").replace(" ", "")

    lines = hex_str.splitlines()
    has_non_hex = any(c not in "0123456789abcdefABCDEF" for c in raw)

    if len(lines) > 1 or has_non_hex:
        # Line-by-line parser: keep only 2-char hex tokens
        cleaned: list[str] = []
        for line in lines:
            parts = line.strip().split()
            hex_tokens = [p for p in parts if len(p) == 2 and is_hex(p)]
            cleaned.extend(hex_tokens)
        raw = "".join(cleaned)

    if not raw:
        raise HexDecodeError("No hex data found in input")

    if len(raw) % 2 != 0:
        raise HexDecodeError(f"Hex string has odd length ({len(raw)}): {raw}")

    try:
        return bytes.fromhex(raw)
    except ValueError as e:
        raise HexDecodeError(str(e)) from e


def bytes_to_hex_dump(data: bytes, width: int = 16) -> str:
    """Pretty hex dump similar to xxd / hexdump -C.

    Args:
        data: Bytes to format.
        width: Bytes per line (default: 16).

    Returns:
        Formatted hex dump string.
    """
    result: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i: i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        addr = f"{i:08x}"
        # Pad hex_part to keep alignment on the last line
        hex_part = hex_part.ljust(width * 3 - 1)
        result.append(f"{addr}  {hex_part}  |{ascii_part}|")
    return "\n".join(result)


# ─── Stream data extraction ───────────────────────────────────────


def extract_follow_stream_data(raw: str) -> Optional[bytes]:
    """Extract raw bytes from 'follow stream' tshark hex output.

    The follow stream output uses ``===`` separators to delimit the data
    section. Lines inside contain hex dumps like::

        00000000  50 4b 03 04 ...

    Args:
        raw: Raw tshark -z follow,... hex output.

    Returns:
        Decoded bytes, or None if no data found.
    """
    hex_str = ""
    capture = False
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("=" * 3):
            capture = not capture
            continue
        if capture and stripped:
            parts = stripped.split()
            hex_tokens = [p for p in parts if len(p) == 2 and is_hex(p)]
            if hex_tokens:
                hex_str += "".join(hex_tokens)

    if hex_str:
        try:
            return bytes.fromhex(hex_str)
        except ValueError:
            return None
    return None


# ─── File type detection ──────────────────────────────────────────

_FILE_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"PK", ".zip", "ZIP archive"),
    (b"\xff\xd8\xff", ".jpg", "JPEG image"),
    (b"\x89PNG", ".png", "PNG image"),
    (b"GIF8", ".gif", "GIF image"),
]


def detect_file_type(data: bytes) -> tuple[str, str]:
    """Detect file type from magic bytes.

    Args:
        data: Raw bytes to analyze.

    Returns:
        ``(file_extension, description)`` tuple.
        Defaults to ``(".bin", "Binary data")``.
    """
    for magic, ext, desc in _FILE_SIGNATURES:
        if data[:len(magic)] == magic:
            return ext, desc
    # Check if it looks like printable text
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    if len(data) > 0 and printable / len(data) > 0.8:
        return ".txt", "Text data"
    return ".bin", "Binary data"


# ─── Base64 ───────────────────────────────────────────────────────


def decode_base64(s: str) -> bytes:
    """Decode a base64 string. Handles URL-safe variant automatically.

    Args:
        s: Base64-encoded string.

    Returns:
        Decoded bytes.

    Raises:
        Base64DecodeError: If input is not valid base64.
    """
    s = s.strip()
    try:
        result = base64.b64decode(s, validate=True)
        if s and not result:
            raise ValueError("Empty result from non-empty input")
        return result
    except Exception:
        try:
            # URL-safe variant: '-' and '_' instead of '+' and '/'
            result = base64.b64decode(s, altchars=b'-_', validate=True)
            if s and not result:
                raise ValueError("Empty result from non-empty input")
            return result
        except Exception as exc:
            raise Base64DecodeError(f"Invalid base64 input: {exc}") from exc


# ─── ZIP ──────────────────────────────────────────────────────────


def try_unzip(
    zip_path: str,
    password: Optional[str] = None,
) -> Optional[list[tuple[str, bytes]]]:
    """Try to extract all files from a zip archive with optional password.

    Supports both traditional ZipCrypto (via stdlib) and AES (via optional pyzipper).

    Validates the password against the first file entry before reading all files,
    which significantly speeds up brute-force attacks.

    Args:
        zip_path: Path to zip file.
        password: Password string (or None for no password).

    Returns:
        List of ``(filename, data)`` tuples on success, ``None`` on failure.
    """
    pwd = password.encode("utf-8") if password else None

    # Try 1: standard zipfile (handles ZipCrypto)
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            if not names:
                return None
            # Early validation: test password on the first entry with CRC check
            try:
                test_data = zf.read(names[0], pwd=pwd)
                info = zf.getinfo(names[0])
                if info.CRC != 0 and zlib.crc32(test_data) != info.CRC:
                    return None
            except NotImplementedError:
                raise  # AES encrypted, fall through to pyzipper (Try 2)
            except (RuntimeError, zipfile.BadZipFile):
                return None
            # Password valid — read all files
            contents: list[tuple[str, bytes]] = []
            for name in names:
                try:
                    data = zf.read(name, pwd=pwd)
                    contents.append((name, data))
                except (RuntimeError, zipfile.BadZipFile):
                    continue
            return contents if contents else None
    except (FileNotFoundError, zipfile.BadZipFile):
        return None
    except Exception:
        pass  # Fall through to pyzipper

    # Try 2: pyzipper (handles AES-encrypted zips)
    try:
        with pyzipper.AESZipFile(zip_path, "r") as zf:
            zf.setpassword(pwd or b"")
            names = zf.namelist()
            if not names:
                return None
            # Early validation: test password on the first entry only
            try:
                zf.read(names[0])
            except Exception:
                return None
            # Password valid — read all files
            contents: list[tuple[str, bytes]] = []
            for name in names:
                try:
                    data = zf.read(name)
                    contents.append((name, data))
                except Exception:
                    continue
            return contents if contents else None
    except Exception:
        pass

    return None


def brute_force_zip(
    zip_path: str,
    max_length: int = 4,
    chars: str = string.digits,
    callback: Optional[Callable[[str], None]] = None,
) -> Optional[tuple[str, list[tuple[str, bytes]]]]:
    """Brute-force zip password by trying all combinations.

    Args:
        zip_path: Path to zip file.
        max_length: Maximum password length to try (default: 4).
        chars: Character set to try (default: digits).
        callback: Optional function called with each attempted password.

    Returns:
        ``(password, [(filename, data), ...])`` on success, ``None`` if not found.
    """
    for length in range(1, max_length + 1):
        for combo in itertools.product(chars, repeat=length):
            pwd = "".join(combo)
            if callback:
                callback(pwd)
            result = try_unzip(zip_path, pwd)
            if result is not None:
                return (pwd, result)
    return None


def brute_force_zip_wordlist(
    zip_path: str,
    wordlist_path: str,
    callback: Optional[Callable[[str], None]] = None,
) -> Optional[tuple[str, list[tuple[str, bytes]]]]:
    """Brute-force zip password using a wordlist file.

    Args:
        zip_path: Path to zip file.
        wordlist_path: Path to wordlist file (one password per line).
        callback: Optional function called with each attempted password.

    Returns:
        ``(password, [(filename, data), ...])`` on success, ``None`` if not found.
    """
    with open(wordlist_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            pwd = line.strip()
            if not pwd:
                continue
            if callback:
                callback(pwd)
            result = try_unzip(zip_path, pwd)
            if result is not None:
                return (pwd, result)
    return None
