"""
File extraction module.
Extracts files from pcap using various methods:
- Extract hex data from filtered packets
- Convert hex dumps to binary files
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.exceptions import TsharkToolError
from core.tshark_wrapper import filter_packets
from core.utils import detect_file_type, hex_dump_to_bytes


def extract_hex_from_filter(
    pcap: str,
    display_filter: str,
    output_dir: str,
    field: str = "data.data",
) -> list[str]:
    """Extract hex data from packets matching a filter, save as binary files.

    Args:
        pcap: Path to pcap file.
        display_filter: Display filter to select packets.
        output_dir: Output directory.
        field: Field to extract hex from (default: data.data).

    Returns:
        List of saved file paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    saved: list[str] = []

    # Get frame numbers too for naming
    raw = filter_packets(
        pcap,
        display_filter,
        fields=["frame.number", field],
    )

    for line in raw.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", 1)
        if len(parts) < 2:
            continue

        frame_num = parts[0].strip()
        hex_str = parts[1].strip()

        if not hex_str:
            continue

        # Skip non-hex data (e.g. text fields like http.request.uri)
        non_hex_ratio = sum(
            1 for c in hex_str if c not in "0123456789abcdefABCDEF: -"
        ) / max(len(hex_str), 1)
        if non_hex_ratio > 0.3:
            # Save as text
            fname = f"extract_frame_{frame_num}.txt"
            path = os.path.join(output_dir, fname)
            with open(path, "w", encoding="utf-8") as f:
                f.write(hex_str)
            saved.append(path)
            continue

        try:
            data = hex_dump_to_bytes(hex_str)
        except (ValueError, AttributeError):
            continue

        if not data:
            continue

        ext, _ = detect_file_type(data)

        fname = f"extract_frame_{frame_num}{ext}"
        path = os.path.join(output_dir, fname)
        with open(path, "wb") as f:
            f.write(data)
        saved.append(path)

    return saved


def extract_zip_from_pcap(pcap: str, output_dir: str) -> list[str]:
    """Extract all ZIP files found in pcap packets.

    Scans common protocols for zip magic bytes (PK.. / 504B...).

    Args:
        pcap: Path to pcap file.
        output_dir: Directory to save extracted zip files.

    Returns:
        List of saved zip file paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    saved: list[str] = []

    # Look for zip data in common places
    filters = [
        "data.data contains 50:4b:03:04",
        "http.file_data contains 50:4b:03:04",
        "ftp-data and data.data contains 50:4b:03:04",
    ]

    def _extract_one(dfilter: str) -> list[str]:
        try:
            return extract_hex_from_filter(pcap, dfilter, output_dir)
        except TsharkToolError:
            return []

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(_extract_one, f): f for f in filters}
        for future in as_completed(futures):
            saved.extend(future.result())

    return saved


def hex_to_file(hex_input: str, output_path: str) -> str:
    """Convert hex dump string to binary file.

    Args:
        hex_input: Hex string (continuous, colon-sep, space-sep, or hexdump).
        output_path: Path to save output file.

    Returns:
        Absolute path to saved file.
    """
    data = hex_dump_to_bytes(hex_input)
    out = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "wb") as f:
        f.write(data)
    return out
