"""
Tshark wrapper — low-level interface to the tshark CLI.
All tshark invocations go through this module.
"""

import os
import platform
import subprocess
from functools import lru_cache
from typing import Any

from core.exceptions import TsharkExecutionError, TsharkNotFoundError

if platform.system() == "Windows":
    TSHARK_PATH = "tshark.exe"
else:
    TSHARK_PATH = "tshark"

_TSHARK_TIMEOUT = 120  # seconds


# ─── Core Execution ──────────────────────────────────────────────────


def _run_tshark(args: list[str]) -> str:
    """Run tshark with *args* and return stdout.

    Results are cached: identical invocations within the same process
    return the cached output, avoiding redundant pcap re-reads.

    Args:
        args: CLI arguments for tshark (without the executable path).

    Returns:
        tshark stdout as a string.

    Raises:
        TsharkNotFoundError: tshark executable not found.
        TsharkExecutionError: tshark returned a non-zero exit code.
    """
    return _tshark_exec(tuple(args))


@lru_cache(maxsize=256)
def _tshark_exec(args: tuple[str, ...]) -> str:
    """Low-level cached tshark invocation (internal)."""
    cmd = [TSHARK_PATH, *args]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
            timeout=_TSHARK_TIMEOUT,
        )
        return proc.stdout
    except subprocess.TimeoutExpired as e:
        raise TsharkExecutionError(
            returncode=-1,
            stderr=f"tshark timed out after {_TSHARK_TIMEOUT}s",
        ) from e
    except subprocess.CalledProcessError as e:
        raise TsharkExecutionError(
            returncode=e.returncode,
            stderr=e.stderr.strip(),
            stdout=e.stdout[:200],
        ) from e
    except FileNotFoundError as e:
        raise TsharkNotFoundError() from e


# ─── Information ─────────────────────────────────────────────────────


def tshark_version() -> str:
    """Return the tshark version string (uncached)."""
    try:
        proc = subprocess.run(
            [TSHARK_PATH, "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
            timeout=10,
        )
        first_line = proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""
        return first_line or "unknown"
    except Exception:
        return "tshark not available"


def get_pcap_info(pcap: str) -> dict[str, Any]:
    """Return basic metadata about a capture file.

    Args:
        pcap: Path to a pcap/pcapng file.

    Returns:
        Dict with keys *raw_info*, *file*, *size_bytes*.
    """
    out = _run_tshark(["-r", pcap, "-q", "-z", "io,phs", "-z", "io,stat,1"])
    return {
        "raw_info": out,
        "file": os.path.abspath(pcap),
        "size_bytes": os.path.getsize(pcap),
    }


def list_protocols(pcap: str) -> str:
    """Print the protocol hierarchy of a capture.

    Args:
        pcap: Path to a pcap/pcapng file.

    Returns:
        Raw tshark output of ``io,phs``.
    """
    return _run_tshark(["-r", pcap, "-q", "-z", "io,phs"])


# ─── Packet Filtering ────────────────────────────────────────────────


def filter_packets(
    pcap: str,
    display_filter: str,
    fields: list[str] | None = None,
    limit: int = 0,
) -> str:
    """Run a display filter and optionally extract specific fields.

    Args:
        pcap: Path to a pcap file.
        display_filter: Wireshark display-filter expression.
        fields: Field names to extract (uses ``-T fields`` mode).
        limit: Maximum number of packets to process (0 = no limit).

    Returns:
        Filtered output as a plain string.
    """
    args = ["-r", pcap]

    if limit > 0:
        args.extend(["-c", str(limit)])

    if fields:
        args.extend(["-T", "fields"])
        for f in fields:
            args.extend(["-e", f])
    else:
        args.extend(["-V"])

    args.extend(["-Y", display_filter])
    return _run_tshark(args)


# ─── Stream Following ────────────────────────────────────────────────


def follow_stream(
    pcap: str,
    protocol: str,
    stream_index: int = 0,
    mode: str = "ascii",
) -> str:
    """Follow a TCP/UDP stream (analogous to Wireshark's *Follow Stream*).

    Args:
        pcap: Path to a pcap file.
        protocol: ``"tcp"`` or ``"udp"``.
        stream_index: Zero-based stream index.
        mode: Output mode — ``"ascii"``, ``"hex"``, or ``"raw"``.

    Returns:
        Stream content as plain text.
    """
    return _run_tshark([
        "-r", pcap,
        "-z", f"follow,{protocol},{mode},{stream_index}",
        "-q",
    ])


# ─── Object Export ───────────────────────────────────────────────────


def export_objects(pcap: str, protocol: str, output_dir: str) -> list[str]:
    """Export embedded objects (files) from a protocol stream.

    Supported protocols include ``http``, ``smb``, ``tftp``, etc.

    Args:
        pcap: Path to a pcap file.
        protocol: Protocol name (e.g. ``"http"``).
        output_dir: Directory in which to write exported files.

    Returns:
        List of absolute paths to the exported files.
    """
    os.makedirs(output_dir, exist_ok=True)
    _run_tshark([
        "-r", pcap,
        "--export-objects", f"{protocol},{output_dir}",
        "-q",
    ])
    return [
        os.path.join(output_dir, f)
        for f in os.listdir(output_dir)
        if os.path.isfile(os.path.join(output_dir, f))
    ]


# ─── Field Extraction ────────────────────────────────────────────────


def extract_raw_field(pcap: str, display_filter: str, field: str) -> list[str]:
    """Extract a raw (hex) field value from matching packets.

    Useful for pulling out ``data`` or ``data.data`` values.

    Args:
        pcap: Path to a pcap file.
        display_filter: Display-filter expression.
        field: Field name (e.g. ``"data.data"``).

    Returns:
        One value (stripped) per matching packet.
    """
    out = _run_tshark([
        "-r", pcap,
        "-Y", display_filter,
        "-T", "fields",
        "-e", field,
    ])
    return [line.strip() for line in out.strip().splitlines() if line.strip()]


def parse_tshark_fields(raw: str, field_names: list[str]) -> list[dict[str, str]]:
    """Parse tshark ``-T fields`` tab-delimited output into structured dicts.

    The first column (frame number) is always mapped to ``"frame"``.
    Subsequent columns are mapped to *field_names* in order.

    Args:
        raw: Raw tshark ``-T fields`` stdout.
        field_names: Semantic names for columns after the frame number.

    Returns:
        List of dicts with keys ``"frame"`` plus *field_names*.
    """
    entries: list[dict[str, str]] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if not parts or not parts[0].isdigit():
            continue
        entry: dict[str, str] = {"frame": parts[0]}
        for i, name in enumerate(field_names):
            idx = i + 1
            if len(parts) > idx and parts[idx]:
                entry[name] = parts[idx]
        entries.append(entry)
    return entries
