"""
FTP protocol analyzer.
Extracts FTP sessions, login credentials, transferred files from pcap.
"""

import os
import re
from typing import Any, Optional

from core.exceptions import TsharkToolError
from core.tshark_wrapper import filter_packets, follow_stream, extract_raw_field, parse_tshark_fields
from core.utils import detect_file_type, extract_follow_stream_data


def analyze_ftp(pcap: str) -> dict[str, Any]:
    """Full FTP analysis: commands, responses, and file transfers.

    Args:
        pcap: Path to pcap/pcapng file.

    Returns:
        dict with keys:
          - sessions: list of FTP command/response conversations
          - credentials: list of (user, pass) tuples found
          - files: list of filenames transferred via FTP-data
          - raw_ftp_data: raw ftp-data output for further processing
    """
    result: dict[str, Any] = {
        "sessions": [],
        "credentials": [],
        "files": [],
    }

    # ── Extract FTP commands & responses ──
    raw = filter_packets(
        pcap, "ftp",
        fields=["frame.number", "ftp.request.command", "ftp.request.arg",
                "ftp.response.code", "ftp.response.arg"],
    )
    result["sessions"] = parse_tshark_fields(raw, ["command", "arg", "response_code", "response_arg"])

    # ── Find login credentials ──
    creds = _find_credentials(raw)
    result["credentials"] = creds

    # ── Find transferred files via ftp-data ──
    ftp_data_out = filter_packets(
        pcap, "ftp-data",
        fields=["frame.number", "data.data"],
    )
    result["raw_ftp_data"] = ftp_data_out

    # ── List filenames from FTP commands ──
    filenames = extract_raw_field(
        pcap,
        "ftp.request.command == \"RETR\" or ftp.request.command == \"STOR\" "
        "or ftp.request.command == \"LIST\" or ftp.request.command == \"NLST\"",
        "ftp.request.arg",
    )
    result["files"] = [f for f in filenames if f]

    return result


def _find_credentials(raw: str) -> list[tuple[str, str]]:
    """Extract USER/PASS pairs from FTP traffic."""
    users: dict[str, str] = {}
    passes: dict[str, str] = {}
    for line in raw.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            cmd = parts[1].strip() if len(parts) > 1 else ""
            if cmd == "USER" and len(parts) >= 3:
                users[parts[0]] = parts[2].strip()
            elif cmd == "PASS" and len(parts) >= 3:
                passes[parts[0]] = parts[2].strip()

    creds: list[tuple[str, str]] = []
    # Match USER/PASS by proximity (same session)
    for frame, user in users.items():
        for p_frame, pwd in passes.items():
            if abs(int(frame) - int(p_frame)) < 10:
                creds.append((user, pwd))
    return creds


def get_ftp_data_streams(pcap: str) -> list[int]:
    """Find TCP stream indices containing FTP data transfers.

    Args:
        pcap: Path to pcap file.

    Returns:
        Sorted list of TCP stream indices for FTP-data connections.
    """
    raw = filter_packets(pcap, "ftp-data", fields=["tcp.stream"])
    streams: set[int] = set()
    for line in raw.strip().splitlines():
        s = line.strip()
        if s.isdigit():
            streams.add(int(s))
        elif s.lstrip("-").isdigit():
            streams.add(int(s))
    return sorted(streams)


def extract_all_ftp_data(pcap: str, output_dir: str) -> list[dict[str, Any]]:
    """Extract all files from FTP data streams with content-type detection.

    Only preserves meaningful files (ZIP, images, text content).
    Directory listings and protocol artifacts are shown in console but not saved.

    Args:
        pcap: Path to pcap file.
        output_dir: Directory to save extracted files.

    Returns:
        List of dicts with keys:
          - path (if saved), stream, type, size, preview, filename_hint.
    """
    os.makedirs(output_dir, exist_ok=True)
    results: list[dict[str, Any]] = []

    def _try_stream(idx: int) -> Optional[dict[str, Any]]:
        data = _extract_ftp_data_bytes(pcap, idx)
        if data is None:
            return None
        ext, desc = detect_file_type(data)

        # Skip tiny protocol artifacts (< 10 bytes, not a known type)
        if len(data) < 10 and ext == ".bin":
            return None

        info: dict[str, Any] = {
            "stream": idx,
            "size": len(data),
            "type": desc,
            "ext": ext,
            "data": data,
        }

        if ext == ".txt":
            # Try to extract filename from directory listing
            text = data.decode("utf-8", errors="replace")
            filename_hint = ""
            for m in re.finditer(r'[\w\-]+\.\w+', text):
                filename_hint = m.group()
                break
            info["preview"] = text[:500]
            info["filename_hint"] = filename_hint
            # Don't save text directory listings as files, but do save text content
            # that looks like a real file (readme, notes, etc.)
            if filename_hint or len(data) > 50:
                out_name = f"ftp_stream_{idx}{ext}"
                if filename_hint:
                    base = filename_hint
                    if base.endswith(ext):
                        base = base[:-len(ext)]
                    out_name = f"ftp_stream_{idx}_{base}{ext}"
                out_path = os.path.join(output_dir, out_name)
                with open(out_path, "wb") as f:
                    f.write(data)
                info["path"] = out_path
            return info

        # Binary files: ZIP, images, etc.
        out_name = f"ftp_stream_{idx}{ext}"
        out_path = os.path.join(output_dir, out_name)
        with open(out_path, "wb") as f:
            f.write(data)
        info["path"] = out_path
        return info

    # Try: actual ftp-data streams
    streams = get_ftp_data_streams(pcap)
    for idx in streams:
        info = _try_stream(idx)
        if info:
            results.append(info)

    # Fallback: trial-and-error on first 10 streams
    if not results:
        for idx in range(10):
            try:
                info = _try_stream(idx)
                if info:
                    results.append(info)
            except TsharkToolError:
                continue

    return results


def _extract_ftp_data_bytes(pcap: str, stream_index: int) -> Optional[bytes]:
    """Extract raw bytes from an FTP data stream.

    Args:
        pcap: Path to pcap file.
        stream_index: TCP stream index.

    Returns:
        Raw bytes if data found, None otherwise.
    """
    try:
        raw_data = follow_stream(pcap, "tcp", stream_index, mode="hex")
    except TsharkToolError:
        return None
    return extract_follow_stream_data(raw_data)


def summary(pcap: str) -> str:
    """Return a human-readable summary of FTP analysis.

    Args:
        pcap: Path to pcap file.

    Returns:
        Formatted summary string.
    """
    info = analyze_ftp(pcap)
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("FTP Analysis Summary")
    lines.append("=" * 60)

    if info["credentials"]:
        lines.append("\n[+] Found credentials:")
        for user, pwd in info["credentials"]:
            lines.append(f"    USER: {user}  PASS: {pwd}")
    else:
        lines.append("\n[-] No credentials found.")

    if info["files"]:
        lines.append("\n[+] Files transferred (via FTP commands):")
        for f in info["files"]:
            lines.append(f"    - {f}")
    else:
        lines.append("\n[-] No file transfers detected.")

    if info["sessions"]:
        lines.append(f"\n[+] FTP sessions: {len(info['sessions'])} packets")
        for s in info["sessions"][:10]:
            cmd = s.get("command", "")
            arg = s.get("arg", "")
            code = s.get("response_code", "")
            rarg = s.get("response_arg", "")
            entry = f"    #[{s.get('frame', '?')}]"
            if cmd:
                entry += f" {cmd}"
            if arg:
                entry += f" {arg}"
            if code:
                entry += f" -> {code}"
            if rarg:
                entry += f" {rarg}"
            lines.append(entry)

    return "\n".join(lines)
