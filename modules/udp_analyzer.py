"""
UDP transport analyzer.
Analyzes UDP endpoints, streams, port distribution, and extracts stream data.
"""

import os
from collections import Counter
from typing import Any, Optional

from core.exceptions import TsharkToolError
from core.tshark_wrapper import filter_packets, follow_stream, parse_tshark_fields
from core.utils import detect_file_type, extract_follow_stream_data

# Common UDP-based services (port -> service name)
_UDP_SERVICES: dict[int, str] = {
    53: "DNS",
    67: "DHCP (server)",
    68: "DHCP (client)",
    69: "TFTP",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    161: "SNMP",
    162: "SNMP-trap",
    389: "LDAP",
    443: "QUIC / HTTPS",
    514: "Syslog",
    520: "RIP",
    623: "IPMI",
    1194: "OpenVPN",
    1434: "MSSQL",
    1701: "L2TP",
    1812: "RADIUS",
    1813: "RADIUS-Accounting",
    1900: "SSDP",
    3389: "RDP (UDP)",
    4500: "IPsec NAT-T",
    5060: "SIP",
    5353: "mDNS",
    5683: "CoAP",
    6343: "sFlow",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}


def _service_name(port: int) -> str:
    """Map UDP port number to service name."""
    return _UDP_SERVICES.get(port, "")


def analyze_udp(pcap: str) -> dict[str, Any]:
    """Full UDP traffic analysis.

    Args:
        pcap: Path to pcap/pcapng file.

    Returns:
        dict with keys: packet_count, stream_count, total_bytes,
        src_ports, dst_ports, endpoints, services, streams.
    """
    raw = filter_packets(
        pcap, "udp",
        fields=[
            "frame.number", "ip.src", "ip.dst",
            "udp.srcport", "udp.dstport",
            "udp.length", "udp.stream",
        ],
    )

    packets = parse_tshark_fields(
        raw,
        ["src_ip", "dst_ip", "src_port", "dst_port", "length", "udp_stream"],
    )

    total_bytes = 0
    src_ports: Counter = Counter()
    dst_ports: Counter = Counter()
    endpoints: Counter = Counter()
    services: Counter = Counter()
    streams: dict[str, Any] = {}

    for p in packets:
        src_ip = p.get("src_ip", "")
        dst_ip = p.get("dst_ip", "")
        src_port = p.get("src_port", "")
        dst_port = p.get("dst_port", "")
        length = p.get("length", "0")
        stream = p.get("udp_stream", "")

        try:
            total_bytes += int(length)
        except ValueError:
            pass

        if src_port:
            sport = int(src_port)
            src_ports[sport] += 1
            svc = _service_name(sport)
            if svc:
                services[svc] += 1

        if dst_port:
            dport = int(dst_port)
            dst_ports[dport] += 1
            svc = _service_name(dport)
            if svc:
                services[svc] += 1

        # Track endpoint pairs
        if src_ip and dst_ip and src_port and dst_port:
            endpoint_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            endpoints[endpoint_key] += 1

        # Track stream metadata
        if stream:
            sid = stream
            try:
                sid = int(stream)
            except ValueError:
                pass
            if sid not in streams:
                streams[sid] = {
                    "endpoints": set(),
                    "packet_count": 0,
                    "total_bytes": 0,
                }
            if src_ip and dst_ip and src_port and dst_port:
                streams[sid]["endpoints"].add(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            streams[sid]["packet_count"] += 1
            try:
                streams[sid]["total_bytes"] += int(length)
            except ValueError:
                pass

    return {
        "packet_count": len(packets),
        "stream_count": len(streams),
        "total_bytes": total_bytes,
        "src_ports": src_ports,
        "dst_ports": dst_ports,
        "endpoints": endpoints,
        "services": services,
        "streams": streams,
    }


def get_udp_streams(pcap: str) -> list[int]:
    """Find all unique UDP stream indices.

    Args:
        pcap: Path to pcap file.

    Returns:
        Sorted list of unique UDP stream indices.
    """
    raw = filter_packets(pcap, "udp", fields=["udp.stream"])
    streams: set[int] = set()
    for line in raw.strip().splitlines():
        s = line.strip()
        if s.isdigit():
            streams.add(int(s))
    return sorted(streams)


def extract_udp_streams(pcap: str, output_dir: str, stream_filter: Optional[int] = None) -> list[dict[str, Any]]:
    """Extract data from UDP streams.

    Uses tshark's follow-stream to reassemble UDP payload data and
    detects file types from magic bytes.

    Args:
        pcap: Path to pcap file.
        output_dir: Directory to save extracted files.
        stream_filter: Optional specific stream index to extract.

    Returns:
        List of dicts with keys: stream, size, type, path, preview.
    """
    os.makedirs(output_dir, exist_ok=True)
    results: list[dict[str, Any]] = []

    streams = [stream_filter] if stream_filter is not None else get_udp_streams(pcap)

    for sid in streams:
        try:
            raw_data = follow_stream(pcap, "udp", sid, mode="hex")
        except TsharkToolError:
            continue

        data = extract_follow_stream_data(raw_data)
        if data is None or len(data) < 4:
            continue

        ext, desc = detect_file_type(data)
        if len(data) < 10 and ext == ".bin":
            continue

        info: dict[str, Any] = {
            "stream": sid,
            "size": len(data),
            "type": desc,
            "ext": ext,
        }

        out_name = f"udp_stream_{sid}{ext}"
        out_path = os.path.join(output_dir, out_name)
        with open(out_path, "wb") as f:
            f.write(data)
        info["path"] = out_path

        # Text preview
        if ext == ".txt":
            text = data.decode("utf-8", errors="replace")
            info["preview"] = text[:500]

        results.append(info)

    return results


def summary(pcap: str) -> str:
    """Return a human-readable summary of UDP analysis.

    Args:
        pcap: Path to pcap file.

    Returns:
        Formatted summary string.
    """
    info = analyze_udp(pcap)
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("UDP Analysis Summary")
    lines.append("=" * 60)

    lines.append(f"\n[+] UDP packets: {info['packet_count']}")
    lines.append(f"[+] UDP streams: {info['stream_count']}")
    lines.append(f"[+] Total UDP payload: {info['total_bytes']:,} bytes")

    # Detected services
    if info["services"]:
        lines.append("\n[+] Detected UDP services:")
        for svc, count in info["services"].most_common(10):
            lines.append(f"    {svc:20s} x{count}")

    # Top source ports
    if info["src_ports"]:
        lines.append("\n[+] Top source ports:")
        for port, count in info["src_ports"].most_common(10):
            svc = _service_name(port)
            label = f"{port}/{svc}" if svc else str(port)
            lines.append(f"    {label:24s} {count:>6d}")

    # Top destination ports
    if info["dst_ports"]:
        lines.append("\n[+] Top destination ports:")
        for port, count in info["dst_ports"].most_common(10):
            svc = _service_name(port)
            label = f"{port}/{svc}" if svc else str(port)
            lines.append(f"    {label:24s} {count:>6d}")

    # Top endpoint pairs
    if info["endpoints"]:
        lines.append("\n[+] Top endpoints:")
        for endpoint, count in info["endpoints"].most_common(10):
            lines.append(f"    {endpoint} x{count}")

    # Stream summary
    if info["streams"]:
        lines.append(f"\n[+] UDP streams ({info['stream_count']} total):")
        # Show top streams by packet count
        top_streams = sorted(
            info["streams"].items(),
            key=lambda x: x[1]["packet_count"],
            reverse=True,
        )[:10]
        for sid, sdata in top_streams:
            pkts = sdata["packet_count"]
            bts = sdata["total_bytes"]
            eps = ", ".join(sorted(sdata["endpoints"])[:2])
            lines.append(f"    stream {sid:>4d}  {pkts:>5d} pkts  {bts:>8,d} bytes  {eps}")
        if len(info["streams"]) > 10:
            lines.append(f"    ... and {len(info['streams']) - 10} more streams")

    lines.append("\n[*] Use --extract to save UDP stream data to disk.")
    return "\n".join(lines)
