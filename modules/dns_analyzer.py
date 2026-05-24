"""
DNS protocol analyzer.
Extracts DNS queries, responses, record types, and suspicious patterns.
"""

import os
from collections import Counter
from typing import Any

from core.tshark_wrapper import extract_raw_field, filter_packets

# Known DNS query type codes
_DNS_TYPES: dict[str, str] = {
    "1": "A", "2": "NS", "3": "MD", "4": "MF", "5": "CNAME",
    "6": "SOA", "7": "MB", "8": "MG", "9": "MR", "10": "NULL",
    "11": "WKS", "12": "PTR", "13": "HINFO", "14": "MINFO",
    "15": "MX", "16": "TXT", "17": "RP", "18": "AFSDB",
    "19": "X25", "20": "ISDN", "21": "RT", "22": "NSAP",
    "23": "NSAP-PTR", "24": "SIG", "25": "KEY", "26": "PX",
    "27": "GPOS", "28": "AAAA", "29": "LOC", "33": "SRV",
    "35": "NAPTR", "36": "KX", "37": "CERT", "39": "DNAME",
    "41": "OPT", "42": "APL", "43": "DS", "44": "SSHFP",
    "45": "IPSECKEY", "46": "RRSIG", "47": "NSEC",
    "48": "DNSKEY", "49": "DHCID", "50": "NSEC3",
    "51": "NSEC3PARAM", "52": "TLSA", "53": "SMIMEA",
    "55": "HIP", "59": "CDS", "60": "CDNSKEY",
    "61": "OPENPGPKEY", "62": "CSYNC", "63": "ZONEMD",
    "64": "SVCB", "65": "HTTPS", "99": "SPF", "108": "EUI48",
    "109": "EUI64", "256": "URI", "257": "CAA",
    "32768": "TA", "32769": "DLV",
}


def _type_name(code: str) -> str:
    """Convert DNS type code to human-readable name."""
    return _DNS_TYPES.get(code, f"TYPE{code}")


def analyze_dns(pcap: str) -> dict[str, Any]:
    """Full DNS traffic analysis.

    Args:
        pcap: Path to pcap/pcapng file.

    Returns:
        dict with keys: packets, queries, responses, top_domains,
        record_types, txt_records, mx_records, errors, suspicious.
    """
    raw = filter_packets(
        pcap, "dns",
        fields=[
            "frame.number", "dns.id", "dns.flags.response",
            "dns.flags.rcode", "dns.qry.name", "dns.qry.type",
            "dns.resp.name", "dns.resp.type", "dns.resp.ttl",
            "dns.a", "dns.aaaa", "dns.cname", "dns.ns",
            "dns.txt", "dns.mx.mail_exchange", "dns.count.answers",
            "dns.count.queries", "dns.count.auth_rr", "dns.count.add_rr",
        ],
    )

    packets = _parse_dns_lines(
        raw,
        ["dns_id", "is_response", "rcode", "qry_name", "qry_type",
         "resp_name", "resp_type", "ttl", "a", "aaaa", "cname", "ns",
         "txt", "mx_exchange", "count_answers", "count_queries",
         "count_auth_rr", "count_add_rr"],
    )

    queries: Counter = Counter()
    responses: list[dict[str, str]] = []
    record_types: Counter = Counter()
    txt_records: list[dict[str, str]] = []
    mx_records: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    suspicious: list[dict[str, str]] = []
    dns_servers: Counter = Counter()

    for p in packets:
        qry_name = p.get("qry_name", "")
        qry_type = p.get("qry_type", "")
        is_resp = p.get("is_response", "")
        rcode = p.get("rcode", "")
        ttl_val = p.get("ttl", "")

        # Track queries
        if qry_name:
            type_name = _type_name(qry_type)
            queries[(qry_name, type_name)] += 1

        # Track record types
        if qry_type:
            record_types[_type_name(qry_type)] += 1

        # Responses
        if is_resp == "1":
            resp_name = p.get("resp_name", "")
            a_val = p.get("a", "")
            aaaa_val = p.get("aaaa", "")
            cname_val = p.get("cname", "")
            txt_val = p.get("txt", "")
            mx_val = p.get("mx_exchange", "")
            frame = p.get("frame", "")

            # Collect response IPs (DNS servers)
            if a_val:
                dns_servers[a_val] += 1
                resp_info = {"frame": frame, "domain": resp_name or qry_name, "ip": a_val, "ttl": ttl_val}
                responses.append(resp_info)
            if aaaa_val:
                resp_info = {"frame": frame, "domain": resp_name or qry_name, "ip": aaaa_val, "ttl": ttl_val}
                responses.append(resp_info)

            # TXT records
            if txt_val:
                txt_records.append({
                    "frame": frame, "domain": resp_name or qry_name,
                    "data": txt_val, "ttl": ttl_val,
                })

            # MX records
            if mx_val:
                mx_records.append({
                    "frame": frame, "domain": resp_name or qry_name,
                    "exchange": mx_val,
                })

            # Check for suspicious patterns
            domain = qry_name or resp_name
            if domain and _is_suspicious(domain):
                suspicious.append({
                    "frame": frame, "domain": domain,
                    "type": _type_name(qry_type),
                    "reason": _suspicious_reason(domain),
                })

            # Error responses
            if rcode and rcode not in ("", "0", 0):
                errors.append({
                    "frame": frame, "domain": resp_name or qry_name,
                    "rcode": rcode,
                })

    return {
        "packet_count": len(packets),
        "top_domains": queries.most_common(10),
        "record_types": record_types,
        "responses": responses,
        "txt_records": txt_records,
        "mx_records": mx_records,
        "errors": errors,
        "suspicious": suspicious,
        "dns_servers": dns_servers.most_common(10),
    }


def _parse_dns_lines(raw: str, field_names: list[str]) -> list[dict[str, str]]:
    """Parse tshark -T fields output for DNS.

    Args:
        raw: Raw tshark -T fields output (tab-delimited).
        field_names: Semantic names for columns after frame number.

    Returns:
        List of parsed packet dicts.
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


def _is_suspicious(domain: str) -> bool:
    """Check if a domain name exhibits suspicious characteristics.

    Indicators: very long length, high entropy, unusual characters.
    """
    if not domain:
        return False
    if len(domain) > 40:
        return True
    # High ratio of hex-looking subdomains (DNS tunneling indicator)
    if "." in domain:
        subdomains = domain.split(".")[:-2]  # exclude TLD + main domain
        for sub in subdomains:
            if len(sub) > 20:
                hex_chars = sum(1 for c in sub if c in "0123456789abcdefABCDEF")
                if len(sub) > 0 and hex_chars / len(sub) > 0.9:
                    return True
    return False


def _suspicious_reason(domain: str) -> str:
    """Return a human-readable reason why a domain is flagged as suspicious."""
    if len(domain) > 40:
        return f"Unusually long domain ({len(domain)} chars)"
    if "." in domain:
        subdomains = domain.split(".")[:-2]
        for sub in subdomains:
            if len(sub) > 20:
                hex_chars = sum(1 for c in sub if c in "0123456789abcdefABCDEF")
                if len(sub) > 0 and hex_chars / len(sub) > 0.9:
                    return f"Hex-encoded subdomain ({len(sub)} chars)"
    return "Suspicious pattern"


def extract_dns_data(pcap: str, output_dir: str) -> list[str]:
    """Extract DNS TXT record data and hex-encoded subdomains to files.

    Useful for recovering data exfiltrated via DNS tunneling.

    Args:
        pcap: Path to pcap file.
        output_dir: Directory to save extracted files.

    Returns:
        List of saved file paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    saved: list[str] = []

    # Extract TXT record data
    txt_values = extract_raw_field(pcap, "dns.txt", "dns.txt")
    combined_txt: list[str] = []
    for val in txt_values:
        if val:
            clean = val.strip('"')
            combined_txt.append(clean)

    if combined_txt:
        txt_path = os.path.join(output_dir, "dns_txt_records.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            for entry in combined_txt:
                f.write(entry + "\n")
        saved.append(txt_path)

    # Extract hex-like subdomains (potential DNS tunneling data)
    raw_dns = extract_raw_field(pcap, "dns.qry.name", "dns.qry.name")
    hex_parts: list[str] = []
    for name in raw_dns:
        if not name:
            continue
        parts = name.rstrip(".").split(".")
        for part in parts:
            clean = part.replace("-", "").replace("_", "")
            if len(clean) >= 16 and len(clean) % 2 == 0:
                hex_chars = sum(1 for c in clean if c in "0123456789abcdefABCDEF")
                if len(clean) > 0 and hex_chars / len(clean) > 0.9:
                    hex_parts.append(clean)

    if hex_parts:
        hex_path = os.path.join(output_dir, "dns_hex_subdomains.txt")
        with open(hex_path, "w", encoding="utf-8") as f:
            for hp in hex_parts:
                f.write(hp + "\n")
                try:
                    decoded = bytes.fromhex(hp)
                    text = decoded.decode("utf-8", errors="replace")
                    if any(32 <= ord(c) < 127 for c in text):
                        f.write(f"  -> decoded: {text}\n")
                except ValueError:
                    pass
        saved.append(hex_path)

    return saved


def summary(pcap: str) -> str:
    """Return a human-readable summary of DNS analysis.

    Args:
        pcap: Path to pcap file.

    Returns:
        Formatted summary string.
    """
    info = analyze_dns(pcap)
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("DNS Analysis Summary")
    lines.append("=" * 60)

    lines.append(f"\n[+] Total DNS packets: {info['packet_count']}")

    # Record type distribution
    if info["record_types"]:
        lines.append("\n[+] DNS record types:")
        for rtype, count in info["record_types"].most_common(10):
            lines.append(f"    {rtype:8s} {count:>6d}")

    # Top queried domains
    if info["top_domains"]:
        lines.append("\n[+] Top queried domains:")
        for (domain, qtype), count in info["top_domains"]:
            lines.append(f"    {domain:40s} [{qtype}] x{count}")

    # DNS servers
    if info["dns_servers"]:
        lines.append("\n[+] DNS servers (response IPs):")
        for ip, count in info["dns_servers"]:
            lines.append(f"    {ip:20s} {count} responses")

    # A/AAAA record responses
    if info["responses"]:
        lines.append(f"\n[+] Resolved IPs ({len(info['responses'])} records):")
        for r in info["responses"][:20]:
            domain = r.get("domain", "")[:35]
            ip = r.get("ip", "")
            ttl = r.get("ttl", "")
            lines.append(f"    #[{r.get('frame','?')}] {domain:35s} -> {ip:20s} (TTL={ttl})")
        if len(info["responses"]) > 20:
            lines.append(f"    ... and {len(info['responses']) - 20} more")

    # MX records
    if info["mx_records"]:
        lines.append(f"\n[+] MX records ({len(info['mx_records'])}):")
        for r in info["mx_records"][:10]:
            lines.append(f"    #[{r.get('frame','?')}] {r.get('domain','?')} -> {r.get('exchange','?')}")

    # TXT records
    if info["txt_records"]:
        lines.append(f"\n[+] TXT records ({len(info['txt_records'])}):")
        for r in info["txt_records"][:10]:
            data = r.get("data", "")
            truncated = data[:100] + ("..." if len(data) > 100 else "")
            lines.append(f"    #[{r.get('frame','?')}] {r.get('domain','?')}")
            lines.append(f"      {truncated}")

    # Error responses
    if info["errors"]:
        lines.append(f"\n[!] DNS errors ({len(info['errors'])}):")
        for e in info["errors"][:10]:
            lines.append(f"    #[{e.get('frame','?')}] {e.get('domain','?')} rcode={e.get('rcode','?')}")

    # Suspicious
    if info["suspicious"]:
        lines.append(f"\n[!] SUSPICIOUS domains ({len(info['suspicious'])}):")
        for s in info["suspicious"]:
            lines.append(f"    #[{s.get('frame','?')}] {s.get('domain','?')}")
            lines.append(f"      Reason: {s.get('reason','?')}")

    if not info["suspicious"] and not info["errors"]:
        lines.append("\n[-] No suspicious patterns or errors detected.")

    lines.append("\n[*] Use --extract to save DNS TXT/hex records to disk.")
    return "\n".join(lines)
