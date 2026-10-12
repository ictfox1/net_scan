# net-scan

A small TCP port scanner with banner grabbing and service detection.
Written in pure Python (stdlib only), no runtime dependencies.

> ⚠️ For authorized testing and education only. Do not scan hosts you
> don't own or don't have explicit permission to test.

## Features

- Concurrent TCP port scanning (`ThreadPoolExecutor`)
- Banner grabbing with idle-timeout reads (handles multi-line banners)
- Service/version detection from banners (SSH, HTTP, FTP, SMTP, Redis, …)
- Port-hint fallback for services without a banner
- Graceful Ctrl+C (cancels pending tasks)
- JSON report export
- Test suite with pytest (~15 cases, no network required)

## Install

```bash
git clone https://github.com/<you>/net-scan.git
cd net-scan
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
# scan a single host, top ports
python scanner.py scanme.nmap.org -p 22,80,443

# scan a range, save JSON report
python scanner.py 192.168.1.1 -p 1-1024 -o report.json

# custom raw probe, throttled
python scanner.py 10.0.0.5 -p 80 --probe "HEAD / HTTP/1.0\r\n\r\n"
```

### Example output

```json
{
  "target": "scanme.nmap.org",
  "ip": "45.33.32.156",
  "timestamp": "2026-10-11T12:00:02Z",
  "open_ports": 3,
  "results": [
    {"port": 22, "state": "open", "service": "ssh", "version": "OpenSSH_6.6.1p1", "banner": "..."}
  ]
}
```

## Tests

```bash
pytest -v
```

## Roadmap

- [ ] CVE enrichment via NVD API
- [ ] CVSS-based risk scoring
- [ ] UDP scan (DNS, SNMP)
- [ ] `--min-severity` filter
- [ ] Docker image
- [ ] GitHub Actions CI

## License

MIT — see [LICENSE](LICENSE).