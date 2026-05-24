"""
HTTP protocol analyzer.
Filters HTTP requests/responses, extracts POST data, files, etc.
"""

import os
from collections import Counter
from typing import Any

from core.tshark_wrapper import (
    extract_raw_field,
    filter_packets,
    parse_tshark_fields,
)
from core.utils import (
    detect_file_type,
    hex_dump_to_bytes,
)


def analyze_http(pcap: str) -> dict[str, Any]:
    """Full HTTP traffic analysis.

    Args:
        pcap: Path to pcap/pcapng file.

    Returns:
        dict with:
          - requests: list of HTTP request summaries
          - responses: list of HTTP response summaries
          - post_requests: filtered POST requests with body
          - exported_files: list of files exported via tshark
    """
    result: dict[str, Any] = {
        "requests": [],
        "responses": [],
        "post_requests": [],
    }

    # ── All HTTP requests ──
    req_raw = filter_packets(
        pcap,
        "http.request",
        fields=[
            "frame.number", "http.request.method", "http.request.uri",
            "http.host", "http.request.full_uri",
            "http.content_type", "http.content_length",
        ],
    )
    result["requests"] = parse_tshark_fields(req_raw, ["method", "uri", "host", "full_uri", "content_type", "content_length"])

    # ── HTTP responses ──
    resp_raw = filter_packets(
        pcap,
        "http.response",
        fields=[
            "frame.number", "http.response.code", "http.response.phrase",
            "http.content_type", "http.content_length",
        ],
    )
    result["responses"] = parse_tshark_fields(resp_raw, ["code", "phrase", "content_type", "content_length"])

    # ── POST requests with body data ──
    result["post_requests"] = _analyze_post_requests(pcap)

    return result


def _analyze_post_requests(pcap: str, extra_filter: str = "") -> list[dict[str, Any]]:
    """Analyze HTTP POST requests with body data."""
    base_filter = 'http.request.method == "POST"'
    full_filter = f"{base_filter} and {extra_filter}" if extra_filter else base_filter

    # Get POST requests with file data
    raw_data = extract_raw_field(
        pcap,
        full_filter,
        "http.file_data",
    )

    # Also get the frame numbers and URIs
    raw_meta = filter_packets(
        pcap,
        full_filter,
        fields=["frame.number", "http.request.uri", "http.host", "http.content_type"],
    )

    requests: list[dict[str, Any]] = []
    meta_lines = raw_meta.strip().splitlines() if raw_meta.strip() else []

    for i, meta in enumerate(meta_lines):
        entry: dict[str, Any] = {"index": i}
        parts = meta.split("\t")
        if len(parts) >= 1 and parts[0].isdigit():
            entry["frame"] = parts[0]
        if len(parts) >= 2:
            entry["uri"] = parts[1]
        if len(parts) >= 3:
            entry["host"] = parts[2]
        if len(parts) >= 4:
            entry["content_type"] = parts[3]

        if i < len(raw_data) and raw_data[i]:
            entry["body_raw"] = raw_data[i]
            body_hex = raw_data[i].replace(":", "").replace("-", "").replace(" ", "")
            entry["body_hex"] = body_hex

            # Check if body starts with zip magic bytes
            body = entry.get("body_hex", "")
            if isinstance(body, str) and body.lower().startswith("504b"):
                entry["is_zip"] = True
            else:
                entry["is_zip"] = False

        requests.append(entry)

    return requests


def extract_post_data(pcap: str, output_dir: str, extra_filter: str = "") -> list[str]:
    """Extract binary data from POST requests and save to files.

    Automatically detects zip files by magic bytes (PK..).

    Args:
        pcap: Path to pcap file.
        output_dir: Directory to save extracted files.
        extra_filter: Additional display filter to narrow results.

    Returns:
        List of saved file paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    saved: list[str] = []

    posts = _analyze_post_requests(pcap, extra_filter=extra_filter)
    for post in posts:
        body_hex = post.get("body_hex", "")
        if not body_hex:
            continue
        try:
            data = hex_dump_to_bytes(body_hex)
        except (ValueError, AttributeError):
            continue

        ext, _ = detect_file_type(data)

        fname = f"http_post_{post.get('frame', str(post['index']))}{ext}"
        path = os.path.join(output_dir, fname)
        with open(path, "wb") as f:
            f.write(data)
        saved.append(path)

    return saved


def extract_response_data(pcap: str, output_dir: str, extra_filter: str = "") -> list[str]:
    """Extract binary data (e.g. images, zips) from HTTP responses.

    Args:
        pcap: Path to pcap file.
        output_dir: Directory to save extracted files.
        extra_filter: Additional display filter to narrow results.

    Returns:
        List of saved file paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    saved: list[str] = []

    base_filter = "http.response and http.file_data"
    full_filter = f"{base_filter} and {extra_filter}" if extra_filter else base_filter

    # Get response body hex data
    raw_data = extract_raw_field(
        pcap,
        full_filter,
        "http.file_data",
    )
    raw_meta = filter_packets(
        pcap,
        full_filter,
        fields=["frame.number", "http.content_type"],
    )

    meta_lines = raw_meta.strip().splitlines() if raw_meta.strip() else []

    for i, meta in enumerate(meta_lines):
        parts = meta.split("\t")
        frame_num = parts[0] if parts and parts[0].isdigit() else str(i)
        content_type = parts[1] if len(parts) > 1 else "application/octet-stream"

        if i >= len(raw_data) or not raw_data[i]:
            continue

        try:
            data = hex_dump_to_bytes(raw_data[i])
        except (ValueError, AttributeError):
            continue

        if not data:
            continue

        # Determine extension
        ext = _ext_from_content_type(content_type, data)

        fname = f"http_response_{frame_num}{ext}"
        path = os.path.join(output_dir, fname)
        with open(path, "wb") as f:
            f.write(data)
        saved.append(path)

    return saved


def _ext_from_content_type(content_type: str, data: bytes) -> str:
    """Map content-type or magic bytes to file extension.

    Args:
        content_type: HTTP Content-Type header value.
        data: Raw response body bytes.

    Returns:
        File extension including leading dot.
    """
    ct = content_type.lower()
    if "zip" in ct or data[:2] == b"PK":
        return ".zip"
    if "jpeg" in ct or "jpg" in ct or data[:3] == b"\xff\xd8\xff":
        return ".jpg"
    if "png" in ct or data[:4] == b"\x89PNG":
        return ".png"
    if "gif" in ct or data[:2] == b"GIF":
        return ".gif"
    if "text" in ct or "html" in ct:
        return ".txt"
    return ".bin"


def summary(pcap: str) -> str:
    """Return a human-readable summary of HTTP analysis.

    Args:
        pcap: Path to pcap file.

    Returns:
        Formatted summary string.
    """
    info = analyze_http(pcap)
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("HTTP Analysis Summary")
    lines.append("=" * 60)

    lines.append(f"\n[+] Total HTTP requests: {len(info['requests'])}")
    if info["post_requests"]:
        lines.append(f"\n[+] POST requests: {len(info['post_requests'])}")
        for p in info["post_requests"]:
            uri = p.get("uri", "?")
            frame = p.get("frame", "?")
            is_zip = p.get("is_zip", False)
            lines.append(f"    #[{frame}] POST {uri}")
            if is_zip:
                lines.append("      +- Contains ZIP data!")
    else:
        lines.append("\n[-] No POST requests found.")

    lines.append(f"\n[+] HTTP responses: {len(info['responses'])}")
    # Annotate response codes with frame IDs
    resp_200 = [r for r in info["responses"] if r.get("code") == "200"]
    resp_other = [r for r in info["responses"] if r.get("code") != "200"]
    if resp_200:
        lines.append(f"    [200 OK] {len(resp_200)} response(s):")
        for r in resp_200[:20]:
            fid = r.get("frame", "?")
            ct = r.get("content_type", "")
            ct_str = f" [{ct}]" if ct else ""
            lines.append(f"      #[{fid}] 200{ct_str}")
        if len(resp_200) > 20:
            lines.append(f"      ... and {len(resp_200) - 20} more")
    if resp_other:
        code_counts = Counter(r.get("code", "?") for r in resp_other)
        for code, count in sorted(code_counts.items()):
            lines.append(f"    [{code}] {count} response(s)")

    lines.append("\n[*] Use --extract to export HTTP POST/response data and objects.")
    return "\n".join(lines)
