"""MMTLS 连接编排：ManualAuth 建会话 + 0-RTT js-login 取码。

移植自 UESTC-MoonCheck 的 firmware/src/wx_mmtls.cpp。
"""
from __future__ import annotations

import json
import os
import re
import socket
import time
from dataclasses import dataclass

from . import dns, wire
from .crypto import sha256, u32be, u16be
from .wire import (
    AppSession,
    LoginMeta,
    PSKEntry,
    Record,
    ShortlinkPacket,
    TrafficKeys,
)

LONGLINK_DOMAIN = "longcloud.weixin.com"
SHORTLINK_DOMAIN = "shortcloud.weixin.com"
MMTLS_PROTOCOL = "mmtlsovertcp"
SHORTLINK_FALLBACK_IP = "120.241.131.173"
LONGLINK_FALLBACK_PORT = 443
SHORTLINK_PORT = 80
MAX_RECORD_BUFFER = 2 * 65535

TYPE8_PREFIX = bytes([0x00, 0x00, 0x00, 0x10, 0x08, 0x00, 0x00,
                      0x00, 0x0B, 0x01, 0x00, 0x00, 0x00, 0x06,
                      0x00, 0x12])
EARLY_ALERT = bytes([0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x01])


class WxResult:
    OK = 0
    INVALID = 1
    AUTH_REJECTED = 2
    TIMEOUT = 3
    NETWORK = 4


class WxError(Exception):
    """带分类的协议错误。"""

    def __init__(self, result: int, detail: str) -> None:
        super().__init__(detail)
        self.result = result
        self.detail = detail


@dataclass
class WxCodeResult:
    result: int = WxResult.NETWORK
    code: str = ""
    error_detail: str = ""


class _SocketReader:
    """按记录边界从 socket 读取 MMTLS 记录。"""

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self.sock = sock
        self.deadline = deadline
        self.buffer = b""
        self.records: list[Record] = []

    def _recv_more(self) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise WxError(WxResult.TIMEOUT, "record read deadline exceeded")
        self.sock.settimeout(min(remaining, 5.0))
        try:
            chunk = self.sock.recv(65536)
        except socket.timeout:
            raise WxError(WxResult.TIMEOUT, "socket timeout while reading records")
        except OSError as error:
            raise WxError(WxResult.NETWORK, f"socket error: {error}") from error
        if not chunk:
            raise WxError(WxResult.NETWORK, "connection closed by peer")
        self.buffer += chunk
        if len(self.buffer) > MAX_RECORD_BUFFER:
            raise WxError(WxResult.INVALID, "record buffer overflow")

    def next_record(self) -> Record:
        while not self.records:
            parsed, consumed = wire.parse_records(self.buffer)
            if parsed:
                self.records.extend(parsed)
                self.buffer = self.buffer[consumed:]
                break
            self._recv_more()
        return self.records.pop(0)


class MmtlsConnection:
    """单次 MMTLS 连接（用完即弃）。"""

    def __init__(self, reader: _SocketReader, sock: socket.socket) -> None:
        self._reader = reader
        self._sock = sock
        self._tx_seq = 0
        self._rx_seq = 0
        self._app_seq = 0
        self._transcript = bytearray()
        self._client_key = None
        self._secret = b""
        self._cert_verify_hash = b""
        self._final_hash = b""
        self._have_final_hash = False
        self._new_session_tickets: list[PSKEntry] = []
        self._handshake_keys = TrafficKeys()
        self._app_keys = TrafficKeys()

    # ---- 底层收发 ----

    def _send_raw(self, data: bytes) -> None:
        try:
            self._sock.sendall(data)
        except OSError as error:
            raise WxError(WxResult.NETWORK, f"socket send failed: {error}") from error

    def _send_plain(self, content_type: int, payload: bytes) -> None:
        self._send_raw(wire.build_record(content_type, payload))
        self._tx_seq += 1

    def _send_encrypted(self, content_type: int, plaintext: bytes,
                        key: bytes, iv: bytes) -> None:
        ciphertext = wire.encrypt_record_payload(
            key, iv, self._tx_seq, content_type, plaintext)
        self._send_raw(wire.build_record(content_type, ciphertext))
        self._tx_seq += 1

    def _recv_plain(self) -> tuple[int, bytes]:
        record = self._reader.next_record()
        self._rx_seq += 1
        return record.content_type, record.payload

    def _recv_decrypted(self, key: bytes, iv: bytes) -> tuple[int, bytes]:
        record = self._reader.next_record()
        plaintext = wire.decrypt_record_payload(
            key, iv, self._rx_seq, record.content_type, record.payload)
        self._rx_seq += 1
        return record.content_type, plaintext

    def _feed(self, data: bytes) -> None:
        self._transcript += data

    def _transcript_hash(self) -> bytes:
        return sha256(bytes(self._transcript))

    # ---- 握手 ----

    def handshake(self) -> None:
        from .crypto import EcdhKey
        self._client_key = EcdhKey()
        self._client_key.generate()
        key2 = EcdhKey()
        key2.generate()
        pub1 = self._client_key.public_key()
        pub2 = key2.public_key()
        client_random = os.urandom(32)
        client_hello = wire.build_client_hello(
            client_random, int(time.time()) & 0xFFFFFFFF, pub1, pub2)
        self._feed(client_hello)
        self._send_plain(wire.CT_HANDSHAKE, client_hello)

        content_type, payload = self._recv_plain()
        if content_type != wire.CT_HANDSHAKE:
            raise WxError(WxResult.INVALID, "expected handshake record")
        message_type, body = wire.split_handshake(payload)
        if message_type != wire.HS_SERVER_HELLO:
            raise WxError(WxResult.INVALID, "expected ServerHello")
        self._feed(payload)
        hello = wire.parse_server_hello(body)
        if hello.cipher != wire.CIPHER_ECDHE or hello.server_group != wire.GROUP_SECP256R1:
            raise WxError(WxResult.INVALID, "unexpected server hello parameters")
        self._secret = self._client_key.mmtls_secret(hello.server_pub_key)
        self._handshake_keys = wire.derive_handshake_keys(
            self._secret, self._transcript_hash())

        for _ in range(64):
            content_type, plaintext = self._recv_decrypted(
                self._handshake_keys.server_key, self._handshake_keys.server_iv)
            if content_type == wire.CT_ALERT:
                raise WxError(WxResult.AUTH_REJECTED, "server sent alert during handshake")
            if content_type != wire.CT_HANDSHAKE:
                raise WxError(WxResult.INVALID, "expected handshake record in flight")
            message_type, hs_body = wire.split_handshake(plaintext)
            if message_type == wire.HS_FINISHED:
                final_hash = self._transcript_hash()
                master = wire.derive_master(self._secret, final_hash)
                self._app_keys = wire.derive_app_keys(master, final_hash)
                expected = wire.finished_verify_data(self._secret, False, final_hash)
                actual = wire.parse_finished(hs_body)
                if actual != expected:
                    raise WxError(WxResult.AUTH_REJECTED,
                                  "server finished verify data mismatch")
                self._final_hash = final_hash
                self._have_final_hash = True
                self._feed(plaintext)
                return
            self._feed(plaintext)
            if message_type == wire.HS_CERT_VERIFY:
                self._cert_verify_hash = self._transcript_hash()
            elif message_type == wire.HS_NEW_SESSION_TICKET:
                self._new_session_tickets.extend(
                    wire.parse_new_session_ticket(hs_body))
        raise WxError(WxResult.INVALID, "handshake did not finish within 64 records")

    def finish_handshake(self) -> None:
        if not self._have_final_hash:
            raise WxError(WxResult.INVALID, "handshake not complete")
        verify_data = wire.finished_verify_data(self._secret, True, self._final_hash)
        finished = wire.build_finished(verify_data)
        self._send_encrypted(wire.CT_HANDSHAKE, finished,
                             self._handshake_keys.client_key,
                             self._handshake_keys.client_iv)

    # ---- 应用数据 ----

    def send_app(self, cmd: int, body: bytes) -> None:
        packet = wire.build_shortlink(cmd, self._app_seq, body)
        self._app_seq += 1
        self._send_encrypted(wire.CT_APP_DATA, packet,
                             self._app_keys.client_key, self._app_keys.client_iv)

    def recv_app(self) -> ShortlinkPacket:
        content_type, plaintext = self._recv_decrypted(
            self._app_keys.server_key, self._app_keys.server_iv)
        if content_type != wire.CT_APP_DATA:
            raise WxError(WxResult.INVALID, "expected application data record")
        packet = wire.parse_shortlink(plaintext)
        if packet.magic != wire.SHORTLINK_MAGIC or packet.total_len != len(plaintext):
            raise WxError(WxResult.INVALID, "malformed shortlink packet")
        return packet

    def take_access_psk(self) -> PSKEntry:
        if not self._cert_verify_hash:
            raise WxError(WxResult.INVALID, "certificate verify hash not captured")
        now = int(time.time())
        for ticket in self._new_session_tickets:
            psk = wire.derive_psk(self._secret, self._cert_verify_hash, ticket.psk_type)
            entry = PSKEntry()
            entry.psk_type = ticket.psk_type
            entry.pre_shared_key = psk
            entry.ticket_entry = ticket.ticket_entry
            entry.lifetime = ticket.lifetime
            entry.expired_at = now + ticket.lifetime
            if entry.psk_type == 1 and entry.expired_at > now:
                return entry
        raise WxError(WxResult.INVALID, "no usable access PSK in session tickets")


# ---- 目标排序 ----

def ordered_longlink_targets(targets: list[dns.Target]) -> list[dns.Target]:
    preferred_ports = [443, 8080, 80, 5000]
    ordered: list[dns.Target] = []
    for port in preferred_ports:
        for target in targets:
            if target.port == port and target not in ordered:
                ordered.append(target)
    for target in targets:
        if target not in ordered:
            ordered.append(target)
    fallback = dns.Target(LONGLINK_DOMAIN, LONGLINK_FALLBACK_PORT)
    ordered = [t for t in ordered if t != fallback]
    if len(ordered) >= 6:
        ordered = ordered[:5]
    ordered.append(fallback)
    return ordered


def shortlink_targets(targets: list[dns.Target]) -> list[dns.Target]:
    result: list[dns.Target] = []
    for target in targets:
        if target.port != SHORTLINK_PORT:
            continue
        if any(existing.ip == target.ip for existing in result):
            continue
        result.append(target)
    if not any(t.ip == SHORTLINK_FALLBACK_IP for t in result):
        result.append(dns.Target(SHORTLINK_FALLBACK_IP, SHORTLINK_PORT))
    return result


# ---- ManualAuth 登录 ----

def _login_target(login_buffer: str, meta: LoginMeta, target: dns.Target,
                  deadline: float) -> tuple[AppSession, PSKEntry]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise WxError(WxResult.TIMEOUT, "no time left for longlink candidate")
    try:
        sock = socket.create_connection((target.ip, target.port), timeout=remaining)
    except OSError as error:
        raise WxError(WxResult.NETWORK,
                      f"connect {target.ip}:{target.port} failed: {error}") from error
    try:
        reader = _SocketReader(sock, deadline)
        conn = MmtlsConnection(reader, sock)
        conn.handshake()
        conn.finish_handshake()

        app_device_id = os.urandom(32)
        body, temp = wire.build_login_body(login_buffer, app_device_id)
        conn.send_app(wire.CMD_MANUAL_AUTH, body)
        response = conn.recv_app()
        if response.cmd != wire.CMD_MANUAL_AUTH:
            raise WxError(WxResult.AUTH_REJECTED, "unexpected ManualAuth response cmd")
        manual_auth_response = wire.parse_login_response(response.body, temp)
        session = wire.extract_session(manual_auth_response)
        psk = conn.take_access_psk()
        session.device_id = meta.device_id
        session.host_app_id = meta.host_app_id
        return session, psk
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---- 0-RTT 短连接 ----

@dataclass
class _ZeroRttRequest:
    body: bytes
    psk: bytes
    client_hello: bytes
    type8: bytes


def _build_zero_rtt_request(entry: PSKEntry, envelope: bytes,
                            now_sec: int) -> _ZeroRttRequest:
    if entry.psk_type != 1 or entry.expired_at <= now_sec:
        raise WxError(WxResult.INVALID, "PSK expired or wrong type")
    timestamp = now_sec & 0xFFFFFFFF
    client_random = os.urandom(32)
    client_hello = wire.build_psk_client_hello(
        client_random, timestamp, entry.ticket_entry)
    early_hash = sha256(client_hello)
    early_keys = wire.derive_psk_one_way_keys(
        entry.pre_shared_key, wire.EARLY_KEYS_LABEL, early_hash)
    type8 = TYPE8_PREFIX + u32be(timestamp)

    type8_ct = wire.encrypt_record_payload(
        early_keys.key, early_keys.iv, 1, wire.CT_PSK_HANDSHAKE, type8)
    envelope_ct = wire.encrypt_record_payload(
        early_keys.key, early_keys.iv, 2, wire.CT_APP_DATA, envelope)
    alert_ct = wire.encrypt_record_payload(
        early_keys.key, early_keys.iv, 3, wire.CT_ALERT, EARLY_ALERT)

    body = wire.build_record(wire.CT_PSK_HANDSHAKE, client_hello)
    body += wire.build_record(wire.CT_PSK_HANDSHAKE, type8_ct)
    body += wire.build_record(wire.CT_APP_DATA, envelope_ct)
    body += wire.build_record(wire.CT_ALERT, alert_ct)
    return _ZeroRttRequest(body=body, psk=entry.pre_shared_key,
                           client_hello=client_hello, type8=type8)


def _check_business_error(response: bytes) -> None:
    """校验业务错误（JSON errcode 或 protobuf base_response）。"""
    if response[:1] == b"{":
        try:
            document = json.loads(response.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            document = None
        if isinstance(document, dict):
            for key in ("errcode", "errCode", "error_code", "retcode", "ret"):
                value = document.get(key)
                if isinstance(value, int) and value != 0:
                    raise WxError(WxResult.AUTH_REJECTED,
                                  f"business error {key}={value}")
    base = wire.pb_get(response, 1)
    if base is None:
        return
    if isinstance(base, int):
        if base != 0:
            raise WxError(WxResult.AUTH_REJECTED, f"business error code={base}")
        return
    nested = wire.pb_get(base, 1)
    if isinstance(nested, int) and nested != 0:
        raise WxError(WxResult.AUTH_REJECTED, f"business error code={nested}")


def _response_code(response: bytes) -> str:
    _check_business_error(response)
    code_bytes = wire.extract_code(response)
    if not code_bytes:
        raise WxError(WxResult.INVALID, "empty login code")
    if any(byte < 0x20 for byte in code_bytes):
        raise WxError(WxResult.INVALID, "login code contains control characters")
    try:
        return code_bytes.decode("ascii")
    except UnicodeDecodeError as error:
        raise WxError(WxResult.INVALID, "login code is not ASCII") from error


def _parse_zero_rtt_response(response_body: bytes, request: _ZeroRttRequest,
                             recv_key: bytes) -> str:
    records, consumed = wire.parse_records(response_body)
    if consumed != len(response_body):
        raise WxError(WxResult.INVALID, "trailing bytes after response records")
    server_hello = None
    app_data = None
    for record in records:
        if record.content_type == wire.CT_HANDSHAKE and server_hello is None:
            server_hello = record.payload
        elif record.content_type == wire.CT_APP_DATA and app_data is None:
            app_data = record.payload
    if server_hello is None or app_data is None:
        raise WxError(WxResult.INVALID, "0-RTT response missing expected records")
    message_type, _body = wire.split_handshake(server_hello)
    if message_type != wire.HS_SERVER_HELLO:
        raise WxError(WxResult.INVALID, "0-RTT response is not ServerHello")

    # 三种 transcript 顺序 × 三个序列号试探（与参考实现一致）
    transcripts = [
        request.client_hello + server_hello,
        request.client_hello + request.type8 + server_hello,
        request.client_hello + server_hello + request.type8,
    ]
    for transcript in transcripts:
        keys = wire.derive_psk_one_way_keys(
            request.psk, wire.LABEL_HANDSHAKE_KEYS, sha256(transcript))
        for sequence in (2, 1, 3):
            try:
                plaintext = wire.decrypt_record_payload(
                    keys.key, keys.iv, sequence, wire.CT_APP_DATA, app_data)
            except Exception:
                continue
            candidates: list[bytes] = []
            try:
                packet = wire.parse_shortlink(plaintext)
                if (packet.magic == wire.SHORTLINK_MAGIC
                        and packet.total_len == len(plaintext)):
                    candidates.append(packet.body)
            except ValueError:
                pass
            candidates.append(plaintext)
            for candidate in candidates:
                try:
                    decrypted = wire.session_decrypt(candidate, recv_key)
                except ValueError:
                    continue
                return _response_code(decrypted)
    raise WxError(WxResult.INVALID, "0-RTT response could not be decrypted")


def _send_zero_rtt(target: dns.Target, psk: PSKEntry, recv_key: bytes,
                   envelope: bytes, deadline: float) -> str:
    now_sec = int(time.time())
    request = _build_zero_rtt_request(psk, envelope, now_sec)
    path = f"/mmtls/{now_sec & 0xFFFFFFFF:08x}"
    headers = [
        ("Accept", "*/*"),
        ("Cache-Control", "no-cache"),
        ("Content-Type", "application/octet-stream"),
        ("Upgrade", "mmtls"),
        ("User-Agent", "MicroMessenger Client"),
        ("X-Online-Host", SHORTLINK_DOMAIN),
    ]
    status, response = dns.http_request(
        target.ip, target.port, SHORTLINK_DOMAIN, "POST", path,
        headers, request.body, deadline)
    if status != 200:
        raise WxError(WxResult.AUTH_REJECTED, f"0-RTT HTTP status {status}")
    return _parse_zero_rtt_response(response, request, recv_key)


# ---- 顶层编排 ----

def get_code(login_buffer: str, app_id: str, timeout_ms: int = 30000) -> WxCodeResult:
    """完整取码：login_buffer + 目标 appid → wx.login code。"""
    result = WxCodeResult()
    if not login_buffer or not app_id:
        result.result = WxResult.INVALID
        result.error_detail = "empty login_buffer or app_id"
        return result
    deadline = time.monotonic() + timeout_ms / 1000.0
    try:
        meta = wire.parse_login_buffer(login_buffer)
    except ValueError as error:
        result.result = WxResult.AUTH_REJECTED
        result.error_detail = f"login_buffer invalid: {error}"
        return result

    domains: dict[str, dns.DomainServers] = {}
    have_dns = dns.fetch_httpdns(min(5.0, max(0.1, deadline - time.monotonic())),
                                 domains)
    long_targets = ordered_longlink_targets(
        dns.targets_for(domains, LONGLINK_DOMAIN, MMTLS_PROTOCOL) if have_dns else [])

    session: AppSession | None = None
    psk: PSKEntry | None = None
    for index, target in enumerate(long_targets):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        share = remaining / (len(long_targets) - index)
        try:
            session, psk = _login_target(
                login_buffer, meta, target, time.monotonic() + share)
            break
        except WxError as error:
            if error.result == WxResult.AUTH_REJECTED:
                result.result = error.result
                result.error_detail = error.detail
                return result
    if session is None or psk is None:
        result.result = WxResult.NETWORK
        result.error_detail = "no longlink candidate succeeded"
        return result

    short_targets = shortlink_targets(
        dns.targets_for(domains, SHORTLINK_DOMAIN, "http") if have_dns else [])
    plaintext = wire.build_jsapi_plaintext(
        session.uin, app_id, b"", wire.JS_LOGIN_CMD_ID, session.host_app_id, b"")
    envelope = wire.build_transfer_packet(session, plaintext)

    for index, target in enumerate(short_targets):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        share = remaining / (len(short_targets) - index)
        try:
            result.code = _send_zero_rtt(
                target, psk, session.recv_key, envelope, time.monotonic() + share)
            result.result = WxResult.OK
            return result
        except WxError as error:
            if error.result == WxResult.AUTH_REJECTED:
                result.result = error.result
                result.error_detail = error.detail
                return result
    result.result = WxResult.NETWORK
    result.error_detail = "no shortlink candidate succeeded"
    return result
