import socket
import argparse
import sys
import concurrent.futures as cct
import logging
import ssl
import json
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

@dataclass
class PortResult:
    port: int
    state: str
    banner: str
    service: str | None
    version: str | None

DEFAULT_PROBES = {
    80:   "HEAD / HTTP/1.0\r\n\r\n",
    8080: "HEAD / HTTP/1.0\r\n\r\n",
    443:  "HEAD / HTTP/1.0\r\n\r\n",
}

SERVICE_PATTERNS = [
    ("ssh",     re.compile(r"^SSH-[\d.]+-(\S+)", re.M)),
    ("http",    re.compile(r"^Server:\s*(.+)$", re.M | re.I)),
    ("smtp",    re.compile(r"^220[ -](?=.*\bE?SMTP\b)(.+)$", re.M | re.I)),
    ("ftp",     re.compile(r"^220[ -](.+)$", re.M)),
    ("redis",   re.compile(r"redis_version:([\d.]+)")),
    ("mongodb", re.compile(r"mongodb", re.I)),
    ("elastic", re.compile(r'"number"\s*:\s*"([^"]+)"')),
]

PORT_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    445: "smb", 993: "imaps", 995: "pop3s", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8080: "http", 27017: "mongodb",
}

MAX_BANNER_BYTES = 65536
IDLE_TIMEOUT = 0.5

def make_ssl_context() -> ssl.SSLContext:
    """For a scanner we intentionally do NOT verify certs — via public API."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _safe_decode(data: bytes) -> str:
    if not data:
        return "unknown"
    try:
        return data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return  f"<binary {len(data)} bytes>"


def _recv_all(sock: socket.socket, max_bytes: int = MAX_BANNER_BYTES,
                idle_timeout: float = IDLE_TIMEOUT) -> bytes:
    """Read until EOF, idle timeout, or max_bytes. Returns all bytes read."""
    chunks: list[bytes] = []
    total = 0
    sock.settimeout(idle_timeout)
    while total < max_bytes:
        try:
            chunk = sock.recv(min(4096, max_bytes - total))
        except (socket.timeout, BlockingIOError):
            break
        except OSError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)

def detect_service(banner: str, port: int) -> tuple[str | None, str | None]:
    if banner and banner != "unknown":
        for name, pattern in SERVICE_PATTERNS:
            m = pattern.search(banner)
            if m:
                version = m.group(1).strip() if m.groups() else None
                return name, version
    return PORT_HINTS.get(port), None

def scan_port(ip: str, port: int, timeout: float, probe: str | None = None) -> PortResult | None:
    """Return (port, banner) if the port is open, else None."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            return None

        banner = "unknown"
        try:
            payload = probe if probe else DEFAULT_PROBES.get(port)
            if port == 443:
                ctx = make_ssl_context()
                with ctx.wrap_socket(s, server_hostname=ip) as ss:
                    if payload:
                        ss.sendall(payload.encode())
                    data = _recv_all(ss)
            else:
                if payload:
                    s.sendall(payload.encode())
                data = _recv_all(s)
            if data:
                banner = _safe_decode(data)
        except OSError as e:
            logging.debug("Port %s: %s", port, e)

        service, version = detect_service(banner, port)
        return PortResult(port, "open", banner, service, version)

def scan(ip: str, ports: list[int], timeout: float, threads: int, probe: str | None = None) -> list[PortResult]:
    """Scan a range of ports concurrently"""
    results: list[PortResult] = []
    with cct.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(scan_port, ip, p, timeout, probe) for p in ports]
        try:
            for future in cct.as_completed(futures):
                res = future.result()
                if res is not None:
                    results.append(res)
                    svc = f"{res.service}/{res.version}" if res.service else "?"
                    first_line = res.banner.splitlines()[0] if res.banner else ""
                    logging.info("[+] %5d/tcp open  %-24s %s", res.port, svc, first_line[:80])
        except KeyboardInterrupt:
            logging.warning("[!] Interrupted, cancelling pending tasks...")
            for f in futures:
                f.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
            raise
    return sorted(results, key=lambda r: r.port)

def parse_ports(ports: str) -> list[int]:
    result: list[int] = []
    for part in ports.split(','):
        part = part.strip()
        if not part:
            continue
        try:
            if '-' in part:
                start, end = map(int, part.split('-', 1))
                if not (1 <= start <= end <= 65535):
                    raise argparse.ArgumentTypeError(f"Invalid port range: {part!r}")
                result.extend(range(start, end + 1))
            else:
                p = int(part)
                if not (1 <= p <= 65535):
                    raise argparse.ArgumentTypeError(f"Invalid port: {part!r}")
                result.append(p)
        except ValueError as e:
            raise argparse.ArgumentTypeError(f"Invalid port spec: {part!r}") from e

    if not result:
        raise argparse.ArgumentTypeError("No ports specified")
    return result

def positive_int(value: int) -> int:
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return n

def positive_float(value: float) -> float:
    n = float(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return n

def build_report(host: str, ip: str, results: list[PortResult]) -> dict:
    return {
        "target": host,
        "ip": ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "open_ports": len(results),
        "results": [asdict(i) for i in results]
    }

def main() -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="TCP scanner")
    parser.add_argument("host", help="target host or IP (must be authorized)")
    parser.add_argument("-p", "--ports", default="21-80", type=parse_ports,
                        help="e.g. 80, 80,443,8000-8100 (default: 21-80)")
    parser.add_argument("--timeout", type=positive_float, default=1.0,
                        help="socket timeout in seconds (default: 1.0)")
    parser.add_argument("--probe", default=None,
                        help="optional raw probe string to send after connecting")
    parser.add_argument("--threads", type=positive_int, default=100, 
                        help="count of workers (default: 100)")
    parser.add_argument("-o", "--output",
                        help="save results to JSON file")
    args = parser.parse_args()
    
    try:
        target_ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        logging.warning('[!] Cannot resolve host: %s', args.host)
        return 1

    ports = args.ports
    logging.info('[*] Scanning %s (%s), %d ports', args.host, target_ip, len(ports))

    try:
        open_ports = scan(target_ip, ports, args.timeout, args.threads, args.probe)
    except KeyboardInterrupt:
        logging.warning('Scanning interrupted by user')
        return 2

    logging.info('[*] Done. %d open ports', len(open_ports))

    if args.output:
        report = build_report(args.host, target_ip, open_ports)
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            logging.info('[*] Report saved to %s', args.output)
        except OSError as e:
            logging.error('[!] Cannot write %s:%s', args.output, e)
            return 3

    return 0

if __name__ == "__main__":
    raise SystemExit(main())