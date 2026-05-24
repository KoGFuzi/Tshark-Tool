#!/usr/bin/env python3
"""
Tshark-tool -- CTF Traffic Analysis Tool
========================================
A CLI tool for analyzing pcap/pcapng files in CTF challenges.
Built on top of tshark (Wireshark CLI).

Usage:
    python tshark_tool.py <command> [options]

Commands:
    info      Show pcap file information
    ftp       Analyze FTP traffic
    http      Analyze HTTP traffic
    dns       Analyze DNS traffic
    udp       Analyze UDP traffic
    all       Full analysis of all protocols
    extract   Extract files from pcap
    hex       Hex dump <-> binary conversion
    base64    Base64 decode
    zip       ZIP file operations (crack passwords)
    analyze   One-stop: analyze + extract
"""

import argparse
import base64
import os
import sys
import re
import zipfile as zf_mod
from typing import Optional
from core.exceptions import PcapNotFoundError, TsharkToolError, Base64DecodeError
from core.logconfig import get_logger, setup_logging
from core.tshark_wrapper import (
    list_protocols, tshark_version, filter_packets,
    extract_raw_field, export_objects,
)
from core.utils import (
    bytes_to_hex_dump,
    hex_dump_to_bytes,
    brute_force_zip,
    brute_force_zip_wordlist,
    decode_base64,
)
from modules.ftp_analyzer import extract_all_ftp_data, summary as ftp_summary
from modules.http_analyzer import (
    extract_post_data, extract_response_data, summary as http_summary,
    _analyze_post_requests,
)
from modules.dns_analyzer import extract_dns_data, summary as dns_summary
from modules.udp_analyzer import extract_udp_streams, summary as udp_summary
from modules.extractor import (
    extract_zip_from_pcap,
    extract_hex_from_filter,
    hex_to_file,
)

# Ensure core/modules are importable from the script's location
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(errors='replace')
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

logger = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tshark-tool",
        description="CTF Traffic Analysis Tool -- powered by tshark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tshark-tool info capture.pcap
  tshark-tool ftp capture.pcap
  tshark-tool http capture.pcap --extract --output ./out
  tshark-tool extract hex "504b0304..." output.zip
  tshark-tool zip crack secret.zip --max-len 4
  tshark-tool analyze capture.pcap -o ./output
        """,
    )

    parser.add_argument(
        "--version", action="version",
        version=f"Tshark-tool 1.0.0 (tshark: {tshark_version()})",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── info ──
    p_info = subparsers.add_parser("info", help="Show pcap file information")
    p_info.add_argument("pcap", help="Path to pcap/pcapng file")

    # ── ftp ──
    p_ftp = subparsers.add_parser("ftp", help="Analyze FTP traffic")
    p_ftp.add_argument("pcap", help="Path to pcap/pcapng file")
    p_ftp.add_argument("--extract", "-e", action="store_true", help="Extract files from FTP-data streams")

    # ── http ──
    p_http = subparsers.add_parser("http", help="Analyze HTTP traffic")
    p_http.add_argument("pcap", help="Path to pcap/pcapng file")
    p_http.add_argument("--extract", "-e", action="store_true", help="Extract files from HTTP POST/response data")
    p_http.add_argument("--output", "-o", default="./extracted", help="Output directory (default: ./extracted)")
    p_http.add_argument("--filter", "-f", help="Additional display filter (e.g. 'http.request.method == POST')")

    # ── all ──
    p_all = subparsers.add_parser("all", help="Full analysis of all protocols in pcap")
    p_all.add_argument("pcap", help="Path to pcap/pcapng file")
    p_all.add_argument("--output", "-o", default="./extracted", help="Output directory (default: ./extracted)")
    p_all.add_argument("--extract", "-e", action="store_true", help="Extract all files found")

    # ── dns ──
    p_dns = subparsers.add_parser("dns", help="Analyze DNS traffic")
    p_dns.add_argument("pcap", help="Path to pcap/pcapng file")
    p_dns.add_argument("--extract", "-e", action="store_true", help="Extract DNS TXT/hex records")
    p_dns.add_argument("--output", "-o", default="./extracted", help="Output directory (default: ./extracted)")

    # ── udp ──
    p_udp = subparsers.add_parser("udp", help="Analyze UDP traffic")
    p_udp.add_argument("pcap", help="Path to pcap/pcapng file")
    p_udp.add_argument("--extract", "-e", action="store_true", help="Extract UDP stream data")
    p_udp.add_argument("--output", "-o", default="./extracted", help="Output directory (default: ./extracted)")
    p_udp.add_argument("--stream", "-s", type=int, help="Specific UDP stream index to follow")

    # ── extract ──
    p_extract = subparsers.add_parser("extract", help="Extract files from pcap or convert data")
    extract_sub = p_extract.add_subparsers(dest="extract_type", help="Extraction type")

    # extract zip
    p_ext_zip = extract_sub.add_parser("zip", help="Extract ZIP files from pcap")
    p_ext_zip.add_argument("pcap", help="Path to pcap/pcapng file")
    p_ext_zip.add_argument("--output", "-o", default="./extracted", help="Output directory")

    # extract hex
    p_ext_hex = extract_sub.add_parser("hex", help="Convert hex dump to binary file")
    p_ext_hex.add_argument("hex_string", help="Hex string (continuous or colon/space separated)")
    p_ext_hex.add_argument("output", help="Output file path")

    # extract hex-file
    p_ext_hex_file = extract_sub.add_parser("hex-file", help="Convert hex dump file to binary")
    p_ext_hex_file.add_argument("hex_file", help="Path to file containing hex dump")
    p_ext_hex_file.add_argument("output", help="Output file path")

    # extract filter
    p_ext_filter = extract_sub.add_parser("filter", help="Extract hex data from packets matching a filter")
    p_ext_filter.add_argument("pcap", help="Path to pcap/pcapng file")
    p_ext_filter.add_argument("filter_expr", help="Display filter expression")
    p_ext_filter.add_argument("--output", "-o", default="./extracted", help="Output directory")
    p_ext_filter.add_argument("--field", default="data.data", help="Field to extract (default: data.data)")

    # ── base64 ──
    p_b64 = subparsers.add_parser("base64", help="Base64 decode")
    p_b64.add_argument("string", help="Base64-encoded string")
    p_b64.add_argument("--output", "-o", help="Save decoded data to file")

    # ── hex ──
    p_hex = subparsers.add_parser("hex", help="Hex dump operations")
    hex_sub = p_hex.add_subparsers(dest="hex_type", help="Hex operation")

    p_hex_decode = hex_sub.add_parser("decode", help="Decode hex string to raw bytes (stdout)")
    p_hex_decode.add_argument("hex_string", help="Hex string to decode")

    p_hex_dump = hex_sub.add_parser("dump", help="Pretty hex dump from file")
    p_hex_dump.add_argument("file", help="Binary file to hex dump")

    # ── zip ──
    p_zip = subparsers.add_parser("zip", help="ZIP file operations")
    zip_sub = p_zip.add_subparsers(dest="zip_type", help="ZIP operation")

    p_zip_info = zip_sub.add_parser("info", help="List contents of a ZIP file")
    p_zip_info.add_argument("zipfile", help="Path to ZIP file")
    p_zip_info.add_argument("--password", "-p", help="Password for encrypted ZIP")

    p_zip_crack = zip_sub.add_parser("crack", help="Brute-force ZIP password")
    p_zip_crack.add_argument("zipfile", help="Path to ZIP file")
    p_zip_crack.add_argument("--max-len", type=int, default=4, help="Max password length (default: 4)")
    p_zip_crack.add_argument("--chars", default="0123456789", help="Character set (default: digits)")
    p_zip_crack.add_argument("--wordlist", "-w", help="Wordlist file (one password per line)")

    # ── analyze (one-stop) ──
    p_analyze = subparsers.add_parser("analyze", help="One-stop: analyze all protocols and extract data")
    p_analyze.add_argument("pcap", help="Path to pcap/pcapng file")
    p_analyze.add_argument("--output", "-o", default="./extracted", help="Output directory (default: ./extracted)")

    return parser


def _print_ftp_file(r: dict, indent: str = ""):
    """Print a single FTP extraction result (type, size, path or stream)."""
    path = r.get("path", "")
    if path:
        print(f"{indent}[{r['type']}] {os.path.basename(path)} ({r['size']:,} bytes)")
    else:
        print(f"{indent}[i] [{r['type']}] stream {r['stream']} ({r['size']:,} bytes)")


def cmd_info(pcap: str):
    """Show pcap file information."""
    check_pcap(pcap)

    print(f"[*] File: {os.path.abspath(pcap)}")
    print(f"[*] Size: {os.path.getsize(pcap):,} bytes")
    print(f"\n[*] TShark version: {tshark_version()}")
    print("\n[*] Protocol Hierarchy:")
    print(list_protocols(pcap))


def cmd_ftp(pcap: str, extract: bool = False):
    """Analyze FTP traffic."""
    check_pcap(pcap)
    print(ftp_summary(pcap))

    if extract:
        out_dir = os.path.join(os.path.dirname(os.path.abspath(pcap)) or ".", "extracted_ftp")
        print(f"\n[*] Extracting FTP-data streams to: {out_dir}")
        results = extract_all_ftp_data(pcap, out_dir)
        if results:
            for r in results:
                _print_ftp_file(r, indent="    ")
                if r.get("preview"):
                    for line in r["preview"].splitlines():
                        print(f"        | {line}")
        else:
            print("[-] No FTP data extracted.")


def cmd_http(pcap: str, extract: bool = False, output: str = "./extracted", extra_filter: str = ""):
    """Analyze HTTP traffic."""
    check_pcap(pcap)
    print(http_summary(pcap))

    if extract:
        post_files = extract_post_data(pcap, output, extra_filter=extra_filter)
        resp_files = extract_response_data(pcap, output, extra_filter=extra_filter)

        if post_files:
            print("\n[+] Extracted POST data files:")
            for f in post_files:
                size = os.path.getsize(f)
                print(f"    {f} ({size:,} bytes)")

        if resp_files:
            print("\n[+] Extracted HTTP response files:")
            for f in resp_files:
                size = os.path.getsize(f)
                print(f"    {f} ({size:,} bytes)")


def _print_extraction_results(ftp_results, zips, http_files, post_files, resp_files,
                               dns_files=None, udp_results=None, indent=""):
    """Print extraction result summaries."""
    if ftp_results:
        print(f"{indent}[+] FTP files: {len(ftp_results)}")
        for r in ftp_results:
            _print_ftp_file(r, indent=indent + "  ")
            if r.get("preview"):
                for line in r["preview"].splitlines()[:3]:
                    print(f"{indent}      | {line}")
    if zips:
        print(f"{indent}[+] ZIP files: {len(zips)}")
        for z in zips:
            print(f"{indent}  - {z}")
    if http_files:
        print(f"{indent}[+] HTTP objects: {len(http_files)}")
        for f in http_files:
            print(f"{indent}  - {f}")
    if post_files:
        print(f"{indent}[+] POST data files: {len(post_files)}")
    if resp_files:
        print(f"{indent}[+] HTTP response files: {len(resp_files)}")
    if dns_files:
        print(f"{indent}[+] DNS data files: {len(dns_files)}")
        for f in dns_files:
            print(f"{indent}  - {f}")
    if udp_results:
        print(f"{indent}[+] UDP streams: {len(udp_results)}")
        for r in udp_results:
            path = r.get("path", "")
            if path:
                print(f"{indent}  stream {r['stream']}: {os.path.basename(path)} [{r['type']}] ({r['size']:,} bytes)")


def _do_extract(pcap: str, output: str) -> tuple:
    """Run all extraction operations and return results."""
    os.makedirs(output, exist_ok=True)

    ftp_results = extract_all_ftp_data(pcap, os.path.join(output, "ftp"))
    zips = extract_zip_from_pcap(pcap, os.path.join(output, "zips"))

    http_files = []
    try:
        http_files = export_objects(pcap, "http", os.path.join(output, "http_objects"))
    except TsharkToolError:
        pass

    post_files = extract_post_data(pcap, os.path.join(output, "http_post"))
    resp_files = extract_response_data(pcap, os.path.join(output, "http_response"))

    dns_files = extract_dns_data(pcap, os.path.join(output, "dns"))
    udp_results = extract_udp_streams(pcap, os.path.join(output, "udp"))

    return ftp_results, zips, http_files, post_files, resp_files, dns_files, udp_results


def cmd_all(pcap: str, output: str = "./extracted", extract: bool = False):
    """Full analysis of all protocols."""
    check_pcap(pcap)
    print(f"[*] Full analysis of: {pcap}")
    print(f"[*] TShark: {tshark_version()}\n")

    print(list_protocols(pcap))
    print(ftp_summary(pcap))
    print()
    print(http_summary(pcap))
    print()
    print(dns_summary(pcap))
    print()
    print(udp_summary(pcap))
    print()

    if extract:
        print(f"[*] Extracting to: {output}")
        ftp_results, zips, http_files, post_files, resp_files, dns_files, udp_results = _do_extract(pcap, output)
        _print_extraction_results(ftp_results, zips, http_files, post_files, resp_files,
                                   dns_files, udp_results, indent="  ")


def cmd_dns(pcap: str, extract: bool = False, output: str = "./extracted"):
    """Analyze DNS traffic."""
    check_pcap(pcap)
    print(dns_summary(pcap))

    if extract:
        os.makedirs(output, exist_ok=True)
        files = extract_dns_data(pcap, output)
        if files:
            print(f"\n[+] DNS data extracted to: {output}")
            for f in files:
                size = os.path.getsize(f)
                print(f"    {f} ({size:,} bytes)")
        else:
            print("\n[-] No DNS data extracted.")


def cmd_udp(pcap: str, extract: bool = False, output: str = "./extracted", stream: int = None):
    """Analyze UDP traffic."""
    check_pcap(pcap)
    print(udp_summary(pcap))

    if extract:
        os.makedirs(output, exist_ok=True)
        if stream is not None:
            print(f"\n[*] Extracting UDP stream {stream}...")
        results = extract_udp_streams(pcap, output, stream_filter=stream)
        if results:
            print(f"\n[+] Extracted {len(results)} UDP stream(s):")
            for r in results:
                path = r.get("path", "")
                if path:
                    print(f"    stream {r['stream']}: {os.path.basename(path)} [{r['type']}] ({r['size']:,} bytes)")
                if r.get("preview"):
                    for line in r["preview"].splitlines()[:3]:
                        print(f"        | {line}")
        else:
            print("\n[-] No UDP stream data extracted.")


def cmd_extract_zip_from_pcap(pcap: str, output: str = "./extracted"):
    """Extract ZIP files from pcap."""
    check_pcap(pcap)
    os.makedirs(output, exist_ok=True)
    print(f"[*] Searching for ZIP files in: {pcap}")
    files = extract_zip_from_pcap(pcap, output)
    if files:
        print(f"[+] Found {len(files)} ZIP file(s):")
        for f in files:
            size = os.path.getsize(f)
            print(f"    {f} ({size:,} bytes)")
    else:
        print("[-] No ZIP files found.")


def cmd_extract_hex(hex_str: str, output: str):
    """Convert hex string to binary file."""
    result = hex_to_file(hex_str, output)
    size = os.path.getsize(result)
    print(f"[+] Saved {size:,} bytes to: {result}")


def cmd_extract_hex_file(hex_file_path: str, output: str):
    """Read hex dump from file and convert to binary."""
    if not os.path.isfile(hex_file_path):
        print(f"[!] File not found: {hex_file_path}")
        sys.exit(1)
    with open(hex_file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    cmd_extract_hex(content, output)


def cmd_extract_filter(pcap: str, filter_expr: str, output: str = "./extracted", field: str = "data.data"):
    """Extract data from packets matching filter."""
    check_pcap(pcap)
    print(f"[*] Filter: {filter_expr}")
    print(f"[*] Field: {field}")
    files = extract_hex_from_filter(pcap, filter_expr, output, field)
    if files:
        print(f"[+] Extracted {len(files)} file(s) to {output}:")
        for f in files:
            size = os.path.getsize(f)
            print(f"    {f} ({size:,} bytes)")
    else:
        print("[-] No data extracted.")


def cmd_base64(string: str, output: Optional[str] = None):
    """Base64 decode."""
    try:
        data = decode_base64(string)
    except Base64DecodeError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    if output:
        with open(output, "wb") as f:
            f.write(data)
        print(f"[+] Decoded {len(data)} bytes -> {output}")
        # Also show text preview
        text = data.decode("utf-8", errors="replace")
        if len(text) > 500:
            text = text[:500] + "\n... (truncated)"
        print(f"\n[*] Preview:\n{text}")
    else:
        # Print to stdout
        try:
            print(data.decode("utf-8"))
        except UnicodeDecodeError:
            print(f"[*] Binary data ({len(data)} bytes), use --output to save")
            print(data.hex()[:200])


def cmd_hex_decode(hex_str: str):
    """Decode hex string to raw bytes."""
    try:
        data = hex_dump_to_bytes(hex_str)
        print(data.decode("utf-8", errors="replace"))
    except Exception as e:
        print(f"[!] Error: {e}")


def cmd_hex_dump(file: str):
    """Pretty hex dump from binary file."""
    if not os.path.isfile(file):
        print(f"[!] File not found: {file}")
        sys.exit(1)
    with open(file, "rb") as f:
        data = f.read()
    print(bytes_to_hex_dump(data))


def cmd_zip_info(zip_path: str, password: Optional[str] = None):
    """List ZIP contents."""
    if not os.path.isfile(zip_path):
        print(f"[!] File not found: {zip_path}")
        sys.exit(1)

    try:
        with zf_mod.ZipFile(zip_path, "r") as zf:
            print(f"[*] ZIP file: {os.path.abspath(zip_path)}")
            print(f"[*] Number of entries: {len(zf.namelist())}")
            for info in zf.infolist():
                flag = "*" if info.flag_bits & 1 else " "
                size = info.file_size
                compress = info.compress_size
                try:
                    crc = f"{info.CRC:08x}"
                except (ValueError, AttributeError):
                    crc = "?"
                print(f"  {flag} {info.filename:30s} {size:>8,d} -> {compress:>8,d}  (crc={crc})")
    except (RuntimeError, zf_mod.BadZipFile) as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


def cmd_zip_crack(zip_path: str, max_len: int = 4, chars: str = "0123456789", wordlist: Optional[str] = None):
    """Crack ZIP password."""
    if not os.path.isfile(zip_path):
        print(f"[!] File not found: {zip_path}")
        sys.exit(1)

    print(f"[*] Cracking: {zip_path}")
    print(f"[*] Method: {'wordlist' if wordlist else f'brute-force (max_len={max_len}, chars={chars})'}")
    print("[*] Trying passwords...")
    sys.stdout.flush()

    attempt_count = 0

    def _callback(pwd: str):
        nonlocal attempt_count
        attempt_count += 1
        if attempt_count % 1000 == 0:
            print(f"    Tried {attempt_count} passwords (current: {pwd})", file=sys.stderr)
        elif attempt_count % 100 == 0:
            print(".", end="", flush=True, file=sys.stderr)

    if wordlist:
        result = brute_force_zip_wordlist(zip_path, wordlist, callback=_callback)
    else:
        result = brute_force_zip(zip_path, max_len, chars, callback=_callback)

    print()  # newline after dots

    if result:
        pwd, contents = result
        print(f"\n[+] PASSWORD FOUND: {pwd}")
        print(f"[+] Total attempts: {attempt_count}")
        for name, data in contents:
            print(f"    Extracted: {name} ({len(data):,} bytes)")
            # Show content preview for text files
            text = data.decode("utf-8", errors="replace")
            if len(text) < 1000:
                print(f"    Content:\n{text}")
    else:
        print(f"\n[-] Password not found after {attempt_count} attempts.")


def cmd_analyze(pcap: str, output: str = "./extracted"):
    """One-stop: analyze all protocols and extract everything."""
    check_pcap(pcap)

    print("=" * 60)
    print(" Tshark-tool -- One-Stop Analysis")
    print("=" * 60)
    print(f" Target: {os.path.abspath(pcap)}")
    print(f" Output: {os.path.abspath(output)}")
    print(f" TShark: {tshark_version()}")
    print()

    print("[1/7] Protocol hierarchy...")
    print(list_protocols(pcap))

    print("\n[2/7] Analyzing FTP...")
    print(ftp_summary(pcap))

    print("\n[3/7] Analyzing HTTP...")
    print(http_summary(pcap))

    print("\n[4/7] Analyzing DNS...")
    print(dns_summary(pcap))

    print("\n[5/7] Analyzing UDP...")
    print(udp_summary(pcap))

    print("\n[6/7] Extracting files...")
    ftp_results, zips, http_files, post_files, resp_files, dns_files, udp_results = _do_extract(pcap, output)
    _print_extraction_results(ftp_results, zips, http_files, post_files, resp_files,
                               dns_files, udp_results, indent="    ")

    print("\n[7/7] Scanning for sensitive information...")
    _scan_sensitive_info(pcap, output, ftp_results)
    print("\n[7/7] Analysis complete!")
    print(f" All extracted files are in: {os.path.abspath(output)}")


def _scan_sensitive_info(pcap: str, output_dir: str, ftp_results: list):
    """Scan analysis results for sensitive information and print to console.
    
    Detects: base64 strings, potential credentials, HTTP POST content,
    interesting text from FTP streams.
    """

    # 1. Show FTP text content (readmes, notes, etc.)
    ftp_texts = [r for r in ftp_results if r.get("ext") == ".txt" and r.get("preview")]
    if ftp_texts:
        print("\n  [+] Text content from FTP streams:")
        for r in ftp_texts:
            hint = f" ({r.get('filename_hint', '')})" if r.get('filename_hint') else ""
            print(f"      stream {r['stream']}{hint}:")
            for line in r["preview"].splitlines()[:8]:
                print(f"        {line}")

    # 2. HTTP POST data content (potential login credentials)
    try:
        posts = _analyze_post_requests(pcap)
        for p in posts:
            body = p.get("body_raw", "")
            if not body:
                continue
            # Try to decode as hex then text
            try:
                decoded = hex_dump_to_bytes(body)
                text = decoded.decode("utf-8", errors="replace")
                # Filter: show only if it contains login-like keywords
                keywords = ["user", "pass", "email", "token", "login", "auth", "key", "flag"]
                if any(k in text.lower() for k in keywords):
                    print(f"\n  [!] Potential credentials in POST #[{p.get('frame','?')}] {p.get('uri','')}:")
                    for line in text.split("&"):
                        if any(k in line.lower() for k in keywords):
                            print(f"      {line}")
            except Exception:
                pass
    except TsharkToolError:
        pass

    # 3. Base64-like strings in plaintext HTTP responses
    try:
        resp_bodies = extract_raw_field(
            pcap,
            "http.response and http.file_data and not http.response.code == 304",
            "http.file_data",
        )
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        found_b64 = set()
        for body in resp_bodies[:100]:
            for match in b64_pattern.findall(body):
                # Skip hex-only strings (they're hex data, not base64)
                hex_chars = sum(1 for c in match if c in "0123456789abcdefABCDEF")
                if hex_chars / len(match) > 0.85:
                    continue
                try:
                    decoded = base64.b64decode(match)
                    text = decoded.decode("utf-8", errors="replace")
                    if any(32 <= ord(c) < 127 for c in text[:50]):
                        found_b64.add(match[:80])
                except Exception:
                    continue
        if found_b64:
            print(f"\n  [+] Potential base64-encoded data ({len(found_b64)} strings):")
            for s in list(found_b64)[:10]:
                # Show first 80 chars with preview
                preview = s[:80]
                print(f"      {preview}")
    except TsharkToolError:
        pass

    # 4. Non-200 HTTP response codes (potential errors/interesting info)
    try:
        raw = filter_packets(
            pcap,
            "http.response and !(http.response.code == 200) and !(http.response.code == 304)",
            fields=["frame.number", "http.response.code", "http.response.phrase"],
        )
        non_ok = [line.strip() for line in raw.strip().splitlines() if line.strip()]
        if non_ok:
            print(f"\n  [!] Non-OK HTTP responses ({len(non_ok)}):")
            for line in non_ok[:10]:
                parts = line.split("\t")
                fid = parts[0] if parts else "?"
                code = parts[1] if len(parts) > 1 else "?"
                phrase = parts[2] if len(parts) > 2 else ""
                print(f"      #[{fid}] {code} {phrase}")
    except TsharkToolError:
        pass


def check_pcap(pcap: str):
    """Validate pcap file exists.

    Raises:
        PcapNotFoundError: If the file does not exist.
    """
    if not os.path.isfile(pcap):
        raise PcapNotFoundError(pcap)


def main():
    setup_logging()
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        match args.command:
            case "info":
                cmd_info(args.pcap)
            case "ftp":
                cmd_ftp(args.pcap, extract=getattr(args, "extract", False))
            case "http":
                cmd_http(args.pcap, extract=getattr(args, "extract", False),
                         output=getattr(args, "output", "./extracted"),
                         extra_filter=getattr(args, "filter", ""))
            case "all":
                cmd_all(args.pcap, output=getattr(args, "output", "./extracted"),
                        extract=getattr(args, "extract", False))
            case "dns":
                cmd_dns(args.pcap, extract=getattr(args, "extract", False),
                        output=getattr(args, "output", "./extracted"))
            case "udp":
                cmd_udp(args.pcap, extract=getattr(args, "extract", False),
                        output=getattr(args, "output", "./extracted"),
                        stream=getattr(args, "stream", None))
            case "extract":
                match args.extract_type:
                    case "zip":
                        cmd_extract_zip_from_pcap(args.pcap, getattr(args, "output", "./extracted"))
                    case "hex":
                        cmd_extract_hex(args.hex_string, args.output)
                    case "hex-file":
                        cmd_extract_hex_file(args.hex_file, args.output)
                    case "filter":
                        cmd_extract_filter(args.pcap, args.filter_expr,
                                           getattr(args, "output", "./extracted"),
                                           getattr(args, "field", "data.data"))
                    case _:
                        print("[!] Specify extraction type: zip, hex, hex-file, filter")
                        sys.exit(1)
            case "base64":
                cmd_base64(args.string, getattr(args, "output", None))
            case "hex":
                match args.hex_type:
                    case "decode":
                        cmd_hex_decode(args.hex_string)
                    case "dump":
                        cmd_hex_dump(args.file)
                    case _:
                        print("[!] Specify hex operation: decode, dump")
                        sys.exit(1)
            case "zip":
                match args.zip_type:
                    case "info":
                        cmd_zip_info(args.zipfile, getattr(args, "password", None))
                    case "crack":
                        cmd_zip_crack(args.zipfile, getattr(args, "max_len", 4),
                                      getattr(args, "chars", "0123456789"),
                                      getattr(args, "wordlist", None))
                    case _:
                        print("[!] Specify zip operation: info, crack")
                        sys.exit(1)
            case "analyze":
                cmd_analyze(args.pcap, getattr(args, "output", "./extracted"))

    except TsharkToolError as e:
        logger.error(str(e))
        print(f"[!] {e}")
        sys.exit(1)
    except (RuntimeError, FileNotFoundError) as e:
        logger.error("Unexpected error: %s", e)
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
