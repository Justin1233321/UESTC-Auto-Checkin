"""微信 HTTPDNS（aedns.weixin.qq.com）与明文 HTTP/1.0 客户端。

移植自 UESTC-MoonCheck 的 firmware/src/wx_dns.cpp。
"""
from __future__ import annotations

import json
import socket
import time
from dataclasses import dataclass, field

NEWDNS_HOST = "aedns.weixin.qq.com"
NEWDNS_BACKUP_IP = "180.153.202.85"
NEWDNS_PATH = "/cgi-bin/default/getdns"
MAX_HTTP_RESPONSE = 64 * 1024


@dataclass(frozen=True)
class Target:
    ip: str
    port: int


@dataclass
class DomainServers:
    ips: list[str] = field(default_factory=list)
    protocols: dict[str, list[int]] = field(default_factory=dict)


def http_request(connect_ip: str, port: int, host_header: str, method: str,
                 path: str, headers: list[tuple[str, str]], body: bytes,
                 deadline: float) -> tuple[int, bytes]:
    """明文 HTTP/1.0 请求（Connection: close，读完整响应）。"""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("http deadline exceeded before connect")
    request = bytearray()
    request += f"{method} {path} HTTP/1.0\r\n".encode("ascii")
    request += f"Host: {host_header}\r\n".encode("ascii")
    request += b"Connection: close\r\n"
    has_length = False
    for name, value in headers:
        request += f"{name}: {value}\r\n".encode("ascii")
        if name.lower() == "content-length":
            has_length = True
    if body and not has_length:
        request += f"Content-Length: {len(body)}\r\n".encode("ascii")
    request += b"\r\n"
    request += body

    with socket.create_connection((connect_ip, port), timeout=remaining) as sock:
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        sock.sendall(bytes(request))
        raw = bytearray()
        while True:
            if deadline - time.monotonic() <= 0:
                break
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            raw += chunk
            if len(raw) > MAX_HTTP_RESPONSE:
                raise ValueError("http response exceeds limit")

    return _parse_http_response(bytes(raw))


def _parse_http_response(raw: bytes) -> tuple[int, bytes]:
    header_end = raw.find(b"\r\n\r\n")
    if header_end < 0:
        raise ValueError("http response missing header terminator")
    header = raw[:header_end]
    body_start = header_end + 4
    text = header.decode("latin-1")
    lines = text.split("\r\n")
    status_line = lines[0]
    if not status_line.startswith("HTTP/"):
        raise ValueError("malformed http status line")
    parts = status_line.split(" ")
    if len(parts) < 2:
        raise ValueError("malformed http status line")
    status = int(parts[1])

    lowered = text.lower()
    if "content-length:" in lowered:
        for line in lines[1:]:
            if line.lower().startswith("content-length:"):
                length = int(line.split(":", 1)[1].strip())
                if length < 0 or length > MAX_HTTP_RESPONSE:
                    raise ValueError("http content-length out of range")
                if len(raw) - body_start < length:
                    raise ValueError("http body truncated")
                return status, raw[body_start:body_start + length]
    if "transfer-encoding: chunked" in lowered:
        return status, _decode_chunked(raw[body_start:])
    return status, raw[body_start:]


def _decode_chunked(data: bytes) -> bytes:
    out = bytearray()
    offset = 0
    while offset < len(data):
        crlf = data.find(b"\r\n", offset)
        if crlf < 0:
            raise ValueError("chunked body missing size terminator")
        size_line = data[offset:crlf].split(b";")[0].strip()
        try:
            chunk_size = int(size_line, 16)
        except ValueError as error:
            raise ValueError("invalid chunk size") from error
        if chunk_size == 0:
            return bytes(out)
        offset = crlf + 2
        if offset + chunk_size + 2 > len(data):
            raise ValueError("chunked body truncated")
        out += data[offset:offset + chunk_size]
        offset += chunk_size + 2
        if len(out) > MAX_HTTP_RESPONSE:
            raise ValueError("chunked body exceeds limit")
    return bytes(out)


def fetch_httpdns(timeout: float,
                  domains: dict[str, DomainServers]) -> bool:
    """拉取 HTTPDNS 域名表；失败返回 False（调用方走兜底）。"""
    path = f"{NEWDNS_PATH}?clientversion=0&devicetype=Windows&uin=0&format=json"
    headers = [("User-Agent", "MicroMessenger Client"), ("Accept", "*/*")]
    deadline = time.monotonic() + timeout
    for host in (NEWDNS_HOST, NEWDNS_BACKUP_IP):
        if deadline - time.monotonic() <= 0:
            break
        try:
            status, body = http_request(
                host, 80, NEWDNS_HOST, "GET", path, headers, b"", deadline)
        except (OSError, ValueError, TimeoutError):
            continue
        if status != 200:
            continue
        try:
            document = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        dns_block = document.get("dns")
        if not isinstance(dns_block, dict) or dns_block.get("retcode") != 0:
            continue
        domain_list = dns_block.get("domainlist")
        if not isinstance(domain_list, list):
            continue

        domains.clear()
        for item in domain_list:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            servers = DomainServers()
            for ip_item in item.get("iplist") or []:
                ip = ip_item.get("ip") if isinstance(ip_item, dict) else None
                if isinstance(ip, str) and ip and ip not in servers.ips:
                    servers.ips.append(ip)
            for proto in item.get("protocollist") or []:
                if not isinstance(proto, dict):
                    continue
                proto_name = proto.get("name")
                if not isinstance(proto_name, str):
                    continue
                ports = [int(p) for p in (proto.get("portlist") or [])
                         if isinstance(p, int) and 0 < p <= 65535]
                if ports:
                    servers.protocols[proto_name] = ports
            domains[name] = servers
        return True
    return False


def targets_for(domains: dict[str, DomainServers], domain: str,
                protocol: str) -> list[Target]:
    servers = domains.get(domain)
    if servers is None:
        return []
    ports = servers.protocols.get(protocol)
    if not ports:
        return []
    return [Target(ip, port) for ip in servers.ips for port in ports]
