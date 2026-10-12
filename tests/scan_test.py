"""Tests for the TCP scan_v1.

Run:
    pip install pytest
    pytest -v scan_v1.py
"""
import argparse
import json
import socket
import ssl
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from scan_v1 import (
    PORT_HINTS,
    PortResult,
    build_report,
    detect_service,
    parse_ports,
    positive_float,
    positive_int,
    scan_port,
)


# ---------- parse_ports ----------

@pytest.mark.parametrize("spec,expected", [
    ("80", [80]),
    ("22", [22]),
    ("21-25", [21, 22, 23, 24, 25]),
    ("22,80,443", [22, 80, 443]),
    ("22,80,443,8000-8002", [22, 80, 443, 8000, 8001, 8002]),
    ("22, 80 , 443", [22, 80, 443]),
    ("65535", [65535]),
    ("1", [1]),
    # tolerant to stray commas / whitespace
    ("22,,80", [22, 80]),
    ("80,", [80]),
    (",80", [80]),
    ("  80  ", [80]),
    ("22, ,80", [22, 80]),
])
def test_parse_ports_valid(spec, expected):
    assert parse_ports(spec) == expected


@pytest.mark.parametrize("spec", [
    "",          # empty → "No ports specified"
    ",",         # only separators
    ",,,",       # same
    "   ",       # whitespace only
    "0",
    "65536",
    "99999",
    "abc",
    "80-",
    "-80",
    "80-79",     # start > end
    "80;443",
    "1-2-3",
    "80-abc",
])
def test_parse_ports_invalid(spec):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_ports(spec)


def test_parse_ports_deduplicates_nothing():
    # we don't dedupe; the caller can if it wants
    assert parse_ports("80,80") == [80, 80]


# ---------- detect_service ----------

@pytest.mark.parametrize("banner,port,expected_service,expected_version", [
    ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", 22, "ssh", "OpenSSH_8.9p1"),
    # smtp is disambiguated by keyword in the banner, not by port
    ("220 metasploitable.localdomain ESMTP Postfix (Ubuntu)", 25,
     "smtp", "metasploitable.localdomain ESMTP Postfix (Ubuntu)"),
    ("220 mail.example.com ESMTP ready", 587,
     "smtp", "mail.example.com ESMTP ready"),
    # ftp on 21 — same 220 code, no SMTP keyword
    ("220 ProFTPD 1.3.5 Server ready", 21, "ftp", "ProFTPD 1.3.5 Server ready"),
    ("220 (vsFTPd 3.0.3)", 21, "ftp", "(vsFTPd 3.0.3)"),
    # http
    ("HTTP/1.1 200 OK\r\nServer: Apache/2.2.8 (Ubuntu) DAV/2\r\n",
     80, "http", "Apache/2.2.8 (Ubuntu) DAV/2"),
    # redis
    ("redis_version:7.0.5\r\n", 6379, "redis", "7.0.5"),
    # fallback: unknown banner → hint from port
    ("unknown", 3389, "rdp", None),
    ("unknown", 23, "telnet", None),
    # no hint, no banner → nothing
    ("unknown", 9999, None, None),
    ("", 9999, None, None),
])
def test_detect_service(banner, port, expected_service, expected_version):
    service, version = detect_service(banner, port)
    assert service == expected_service
    assert version == expected_version


def test_detect_service_port_hint_covers_common_ports():
    for p in (22, 23, 25, 80, 443, 3306, 3389, 6379, 27017):
        assert p in PORT_HINTS

# ---------- scan_port ----------

def _fake_socket(recv_data: bytes = b"", connect_result: int = 0) -> MagicMock:
    sock = MagicMock()
    sock.connect_ex.return_value = connect_result
    sock.recv.return_value = recv_data
    sock.__enter__ = MagicMock(return_value=sock)
    sock.__exit__ = MagicMock(return_value=False)
    return sock


def test_scan_port_open_ssh(monkeypatch):
    fake = _fake_socket(recv_data=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
    monkeypatch.setattr("scan_v1.socket.socket", lambda *a, **kw: fake)

    res = scan_port("127.0.0.1", 22, timeout=0.5)

    assert res is not None
    assert isinstance(res, PortResult)
    assert res.port == 22
    assert res.state == "open"
    assert res.service == "ssh"
    assert res.version == "OpenSSH_8.9p1"


def test_scan_port_closed_returns_none(monkeypatch):
    fake = _fake_socket(connect_result=111)  # ECONNREFUSED
    monkeypatch.setattr("scan_v1.socket.socket", lambda *a, **kw: fake)

    assert scan_port("127.0.0.1", 22, timeout=0.5) is None


def test_scan_port_open_but_no_banner(monkeypatch):
    fake = _fake_socket(recv_data=b"")
    monkeypatch.setattr("scan_v1.socket.socket", lambda *a, **kw: fake)

    res = scan_port("127.0.0.1", 23, timeout=0.5)

    assert res is not None
    assert res.banner == "unknown"
    assert res.service == "telnet"
