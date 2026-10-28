"""MMTLS / ManualAuth / js-login 协议编解码。

移植自 UESTC-MoonCheck 的 firmware/src/wx_wire.cpp。
纯编解码层，不含网络；网络编排见 mmtls.py。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .crypto import (
    EcdhKey,
    encode_varint,
    expand_label,
    gcm_decrypt_layout,
    gcm_encrypt_layout,
    hkdf_expand,
    hkdf_extract,
    hmac_sha256,
    lz4_all_literal,
    lz4_decompress,
    pb_get,
    pb_get_bytes,
    pb_len,
    pb_var,
    read_varint,
    sha256,
    u8,
    u16be,
    u32be,
    u64be,
)

# ---- 协议常量（与参考实现严格一致，勿改） ----
RECORD_VERSION = 0xF103
CT_ALERT = 0x15
CT_HANDSHAKE = 0x16
CT_APP_DATA = 0x17
CT_PSK_HANDSHAKE = 0x19
HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02
HS_NEW_SESSION_TICKET = 0x04
HS_CERT_VERIFY = 0x0F
HS_FINISHED = 0x14
CIPHER_ECDHE = 0xC02B
CIPHER_PSK = 0x00A8
EXT_KEY_SHARE = 0x01
GROUP_SECP256R1 = 0x01
SHORTLINK_MAGIC = 0x1110
SHORTLINK_VERSION = 0x076D
TRANSFER_CMD = 0x0B41
JS_LOGIN_CMD_ID = 1029
CMD_MANUAL_AUTH = 0x0D7D
CLIENT_VERSION = 524545
APP_VERSION = 1901
SESSION_CLIENT_VERSION = 1661404927
AES_IV_LEN = 12
GCM_TAG_LEN = 16

# ManualAuth 服务器静态公钥（公开常量，P-256 未压缩点）
_MANUAL_AUTH_SERVER_PUB = bytes([
    0x04, 0xef, 0x87, 0x87, 0x6d, 0x64, 0x78, 0xb1, 0x5f, 0x17, 0x96, 0xea,
    0xb1, 0x20, 0x68, 0x61, 0x05, 0x41, 0x17, 0x3b, 0x71, 0x76, 0xb6, 0x7f,
    0x1d, 0xcc, 0x86, 0x68, 0x3e, 0x90, 0x1a, 0xcd, 0x44, 0xd1, 0x8b, 0x4a,
    0xc3, 0x69, 0x38, 0x25, 0x1d, 0x08, 0x12, 0xdd, 0x0c, 0xf8, 0x42, 0xaa,
    0x2d, 0x6c, 0xbb, 0x81, 0x15, 0x71, 0x2d, 0x1c, 0x00, 0x87, 0xdc, 0xef,
    0xc1, 0x4a, 0x44, 0xcd, 0x58])

HOST_APP_ID_DEFAULT = "wxd44977328b36e647"
ILINK_DEVICE = "ilinkapp_060000b7b93f6c"
TRANSFER_URL = "/ilink/ilinkapp/mp/wxaruntime_transfer"
TRANSFER_HOST = "shortcloud.weixin.com"
JS_LOGIN_URL = "/cgi-bin/mmbiz-bin/js-login"
WINDOWS_PLUGIN = "WindowsxWebPlugin"
WINDOWS_NAME = "Windows"
UNIFIED_PC_WINDOWS = "UnifiedPCWindows"
SESSION_KEY_LITERAL = "sessionkey"

LABEL_EXPANDED_SECRET = "expanded secret"
LABEL_HANDSHAKE_KEYS = "handshake key expansion"
LABEL_APP_DATA_KEYS = "application data key expansion"
LABEL_CLIENT_FINISHED = "client finished"
LABEL_SERVER_FINISHED = "server finished"
LABEL_PSK_ACCESS = "PSK_ACCESS"
LABEL_PSK_REFRESH = "PSK_REFRESH"
EARLY_KEYS_LABEL = "early data key expansion"


def manual_auth_server_pub() -> bytes:
    return _MANUAL_AUTH_SERVER_PUB


# ---- 数据结构 ----

@dataclass
class Record:
    content_type: int
    payload: bytes


@dataclass
class ServerHello:
    server_random: bytes = b""
    cipher: int = 0
    server_group: int = 0
    server_pub_key: bytes = b""


@dataclass
class ShortlinkPacket:
    total_len: int = 0
    magic: int = 0
    ver: int = 0
    cmd: int = 0
    seq: int = 0
    body: bytes = b""


@dataclass
class TrafficKeys:
    client_key: bytes = b""
    server_key: bytes = b""
    client_iv: bytes = b""
    server_iv: bytes = b""
    # 单向（28 字节块派生）时的 key / iv
    key: bytes = b""
    iv: bytes = b""


@dataclass
class AppSession:
    send_key: bytes = b""
    recv_key: bytes = b""
    f9: bytes = b""
    uin: int = 0
    ticket: bytes = b""
    device_id: bytes = b""
    host_app_id: bytes = b""


@dataclass
class PSKEntry:
    psk_type: int = 0
    pre_shared_key: bytes = b""
    ticket_entry: bytes = b""
    lifetime: int = 0
    expired_at: int = 0


@dataclass
class LoginMeta:
    ticket: bytes = b""
    device_id: bytes = b""
    host_app_id: bytes = b""


@dataclass
class WpkgHead:
    ints: list[tuple[int, int]] = field(default_factory=list)
    byts: list[tuple[int, bytes]] = field(default_factory=list)
    offset: int = 0


@dataclass
class ManualAuthTemp:
    """ManualAuth 一次性中间态。"""
    ephemeral: EcdhKey | None = None
    okm: bytes = b""
    comp_body: bytes = b""


# ---- MMTLS 记录 / 握手 ----

def build_record(content_type: int, payload: bytes) -> bytes:
    return u8(content_type) + u16be(RECORD_VERSION) + u16be(len(payload)) + payload


def parse_records(data: bytes) -> tuple[list[Record], int]:
    """解析完整记录。返回 (records, consumed)；不完整尾部不消费。"""
    out: list[Record] = []
    offset = 0
    known = {CT_ALERT, CT_HANDSHAKE, CT_APP_DATA, CT_PSK_HANDSHAKE, 0x14}
    while offset + 5 <= len(data):
        content_type = data[offset]
        version = (data[offset + 1] << 8) | data[offset + 2]
        length = (data[offset + 3] << 8) | data[offset + 4]
        if version != RECORD_VERSION or content_type not in known:
            raise ValueError("unexpected record header")
        end = offset + 5 + length
        if end > len(data):
            break  # 不完整，等待更多数据
        out.append(Record(content_type, data[offset + 5:end]))
        offset = end
    return out, offset


def build_handshake(message_type: int, body: bytes) -> bytes:
    payload = u8(message_type) + body
    return u32be(len(payload)) + payload


def split_handshake(payload: bytes) -> tuple[int, bytes]:
    """返回 (message_type, body)。"""
    if len(payload) < 5:
        raise ValueError("handshake payload too short")
    total = int.from_bytes(payload[0:4], "big")
    if total == 0 or total + 4 > len(payload):
        raise ValueError("invalid handshake length")
    return payload[4], payload[5:total + 4]


def build_client_hello(client_random32: bytes, timestamp: int,
                       g1_public65: bytes, g2_public65: bytes) -> bytes:
    if len(client_random32) != 32:
        raise ValueError("client random must be 32 bytes")
    if len(g1_public65) != 65 or len(g2_public65) != 65:
        raise ValueError("key shares must be 65 bytes")
    body = bytearray()
    body += bytes([0x03, 0xF1, 0x01])
    body += u16be(CIPHER_ECDHE)
    body += client_random32
    body += u32be(timestamp)
    # key_shares 扩展
    key_shares = bytearray()
    key_shares += bytes([0x00, 0x10, 0x02])
    for group, key in ((GROUP_SECP256R1, g1_public65), (0x02, g2_public65)):
        share = u32be(group) + u16be(len(key)) + key
        key_shares += u32be(len(share)) + share
    key_shares += bytes([0x00, 0x00, 0x00, 0x01])
    extension = u8(EXT_KEY_SHARE) + u32be(len(key_shares)) + bytes(key_shares)
    body += u32be(len(extension)) + extension
    return build_handshake(HS_CLIENT_HELLO, bytes(body))


def build_psk_client_hello(client_random32: bytes, timestamp: int,
                           ticket_entry: bytes) -> bytes:
    if len(client_random32) != 32:
        raise ValueError("client random must be 32 bytes")
    body = bytearray()
    body += bytes([0x03, 0xF1, 0x01])
    body += u16be(CIPHER_PSK)
    body += client_random32
    body += u32be(timestamp)
    extension_data = bytearray()
    extension_data += bytes([0x00, 0x0F, 0x01])
    extension_data += u32be(len(ticket_entry)) + ticket_entry
    extension = u8(EXT_KEY_SHARE) + u32be(len(extension_data)) + bytes(extension_data)
    body += u32be(len(extension)) + extension
    return build_handshake(HS_CLIENT_HELLO, bytes(body))


def parse_server_hello(body: bytes) -> ServerHello:
    if len(body) < 40:
        raise ValueError("server hello too short")
    out = ServerHello()
    out.cipher = (body[2] << 8) | body[3]
    out.server_random = body[4:36]
    ext_len = int.from_bytes(body[36:40], "big")
    ext_start = 40
    ext_end = ext_start + ext_len
    if ext_end > len(body):
        raise ValueError("server hello extension overruns body")
    ext = body[ext_start:ext_end]
    out.server_group = GROUP_SECP256R1
    if ext and ext[0] == EXT_KEY_SHARE:
        if len(ext) < 7:
            raise ValueError("key share extension too short")
        cursor = 7
        if cursor + 6 > len(ext):
            raise ValueError("truncated server key share")
        out.server_group = int.from_bytes(ext[cursor:cursor + 4], "big")
        cursor += 4
        key_len = (ext[cursor] << 8) | ext[cursor + 1]
        cursor += 2
        if cursor + key_len > len(ext) or key_len != 65:
            raise ValueError("invalid server public key length")
        out.server_pub_key = ext[cursor:cursor + key_len]
    else:
        # 后备：扫描 0x00 0x41 0x04（65 字节未压缩点）
        limit = len(ext) - 67 + 1 if len(ext) >= 67 else 0
        for i in range(limit):
            if ext[i] == 0x00 and ext[i + 1] == 0x41 and ext[i + 2] == 0x04:
                out.server_pub_key = ext[i + 2:i + 2 + 65]
                break
    if not out.server_pub_key:
        raise ValueError("server public key not found")
    return out


def build_finished(verify_data32: bytes) -> bytes:
    if len(verify_data32) != 32:
        raise ValueError("finished verify data must be 32 bytes")
    return build_handshake(HS_FINISHED, u16be(32) + verify_data32)


def parse_finished(body: bytes) -> bytes:
    if len(body) < 2:
        raise ValueError("finished body too short")
    length = (body[0] << 8) | body[1]
    if length != len(body) - 2:
        raise ValueError("finished length mismatch")
    return body[2:]


def parse_new_session_ticket(body: bytes) -> list[PSKEntry]:
    if not body:
        raise ValueError("empty new session ticket")
    count = body[0]
    offset = 1
    out: list[PSKEntry] = []
    for _ in range(count):
        if offset + 4 > len(body):
            raise ValueError("truncated ticket length")
        entry_len = int.from_bytes(body[offset:offset + 4], "big")
        offset += 4
        if entry_len < 5 or offset + entry_len > len(body):
            raise ValueError("invalid ticket entry")
        entry = body[offset:offset + entry_len]
        offset += entry_len
        psk = PSKEntry()
        psk.psk_type = entry[0]
        psk.lifetime = int.from_bytes(entry[1:5], "big")
        psk.ticket_entry = entry  # 整个 entry 即 ticket
        out.append(psk)
    if offset != len(body):
        raise ValueError("trailing bytes after ticket list")
    return out


# ---- 记录加解密（AAD = seq || type || 0xF103 || cipherLen） ----

def build_record_aad(sequence: int, content_type: int, cipher_len: int) -> bytes:
    return u64be(sequence) + u8(content_type) + u16be(RECORD_VERSION) + u16be(cipher_len)


def _record_nonce(iv: bytes, sequence: int) -> bytes:
    if len(iv) != AES_IV_LEN:
        raise ValueError("record IV must be 12 bytes")
    nonce = bytearray(iv)
    seq_bytes = u64be(sequence)
    for i in range(8):
        nonce[AES_IV_LEN - 8 + i] ^= seq_bytes[i]
    return bytes(nonce)


def encrypt_record_payload(key: bytes, iv: bytes, sequence: int, content_type: int,
                           plaintext: bytes) -> bytes:
    from .crypto import aes_gcm_encrypt
    aad = build_record_aad(sequence, content_type, len(plaintext) + GCM_TAG_LEN)
    return aes_gcm_encrypt(key, _record_nonce(iv, sequence), aad, plaintext)


def decrypt_record_payload(key: bytes, iv: bytes, sequence: int, content_type: int,
                           ciphertext: bytes) -> bytes:
    from .crypto import aes_gcm_decrypt
    aad = build_record_aad(sequence, content_type, len(ciphertext))
    return aes_gcm_decrypt(key, _record_nonce(iv, sequence), aad, ciphertext)


# ---- MMTLS 密钥派生 ----

def derive_master(secret: bytes, handshake_hash: bytes) -> bytes:
    return expand_label(secret, LABEL_EXPANDED_SECRET, handshake_hash, 32)


def _split_bi_keys(key_block: bytes) -> TrafficKeys:
    if len(key_block) != 56:
        raise ValueError("bidirectional key block must be 56 bytes")
    out = TrafficKeys()
    out.client_key = key_block[0:16]
    out.server_key = key_block[16:32]
    out.client_iv = key_block[32:44]
    out.server_iv = key_block[44:56]
    return out


def derive_handshake_keys(secret: bytes, handshake_hash: bytes) -> TrafficKeys:
    return _split_bi_keys(expand_label(secret, LABEL_HANDSHAKE_KEYS, handshake_hash, 56))


def derive_app_keys(master: bytes, handshake_hash: bytes) -> TrafficKeys:
    return _split_bi_keys(expand_label(master, LABEL_APP_DATA_KEYS, handshake_hash, 56))


def finished_verify_data(secret: bytes, is_client: bool, handshake_hash: bytes) -> bytes:
    """两步（与参考实现一致）：先派生 finished_key，再对握手哈希做 HMAC。"""
    label = LABEL_CLIENT_FINISHED if is_client else LABEL_SERVER_FINISHED
    finished_key = expand_label(secret, label, b"", 32)
    return hmac_sha256(finished_key, handshake_hash)


def derive_psk(secret: bytes, cert_verify_hash: bytes, psk_type: int) -> bytes:
    label = LABEL_PSK_ACCESS if psk_type == 1 else LABEL_PSK_REFRESH
    return expand_label(secret, label, cert_verify_hash, 32)


def derive_psk_one_way_keys(psk: bytes, label: str, hash_value: bytes) -> TrafficKeys:
    block = expand_label(psk, label, hash_value, 28)
    out = TrafficKeys()
    out.key = block[0:16]
    out.iv = block[16:28]
    return out


# ---- 短连接包 ----

def build_shortlink(cmd: int, seq: int, body: bytes, version: int = 0) -> bytes:
    if version == 0:
        version = SHORTLINK_VERSION
    return (u32be(16 + len(body)) + u16be(SHORTLINK_MAGIC) + u16be(version)
            + u32be(cmd) + u32be(seq) + body)


def parse_shortlink(packet: bytes) -> ShortlinkPacket:
    if len(packet) < 16:
        raise ValueError("shortlink packet too short")
    out = ShortlinkPacket()
    out.total_len = int.from_bytes(packet[0:4], "big")
    out.magic = (packet[4] << 8) | packet[5]
    out.ver = (packet[6] << 8) | packet[7]
    out.cmd = int.from_bytes(packet[8:12], "big")
    out.seq = int.from_bytes(packet[12:16], "big")
    if out.total_len < 16 or out.total_len > len(packet):
        raise ValueError("invalid shortlink total length")
    out.body = packet[16:out.total_len]
    return out


# ---- WPKG 头 ----

def wpkg_head(ints: list[tuple[int, int]],
              byts: list[tuple[int, bytes]]) -> bytes:
    """组 WPKG 头（ints/byts 均按字段号升序；参考实现要求）。"""
    result = bytearray(encode_varint(1))
    for field_no, value in ints:
        result += encode_varint(field_no) + encode_varint(value)
    result += encode_varint(0)
    for field_no, value in byts:
        result += encode_varint(field_no) + encode_varint(len(value)) + value
    prefix_length = len(result)
    result.append(0)
    result += encode_varint(prefix_length + 1)
    return bytes(result)


def decode_wpkg_head(data: bytes) -> WpkgHead:
    offset = 0
    version, offset = read_varint(data, offset)
    if version != 1:
        raise ValueError("unexpected WPKG version")
    out = WpkgHead()
    while True:
        field_no, offset = read_varint(data, offset)
        if field_no == 0:
            break
        if field_no > ((1 << 29) - 1):
            raise ValueError("WPKG field number out of range")
        value, offset = read_varint(data, offset)
        out.ints.append((field_no, value))
    while True:
        field_no, offset = read_varint(data, offset)
        if field_no == 0:
            break
        if field_no > ((1 << 29) - 1):
            raise ValueError("WPKG field number out of range")
        length, offset = read_varint(data, offset)
        if length > len(data) - offset:
            raise ValueError("WPKG byte field overruns data")
        out.byts.append((field_no, data[offset:offset + length]))
        offset += length
    trailer_offset = offset
    declared, offset = read_varint(data, offset)
    if declared != trailer_offset:
        raise ValueError("WPKG trailer length mismatch")
    out.offset = offset
    return out


# ---- login_buffer / ManualAuth ----

def parse_login_buffer(login_buffer_b64: str) -> LoginMeta:
    import base64
    try:
        raw = base64.b64decode(login_buffer_b64, validate=True)
    except Exception as error:
        raise ValueError("login_buffer is not valid base64") from error
    if not raw or len(raw) > 4096:
        raise ValueError("login_buffer size out of range")
    f1 = pb_get_bytes(raw, 1)
    f2 = pb_get_bytes(raw, 2)
    if not f1:
        raise ValueError("login_buffer missing ticket field")
    if not f2:
        raise ValueError("login_buffer missing device id field")
    out = LoginMeta()
    out.ticket = f1
    out.device_id = f2
    out.host_app_id = pb_get_bytes(raw, 3) or b""
    return out


def _build_manual_auth_request(meta: LoginMeta, app_device_id: bytes) -> bytes:
    app_base = pb_len(1, app_device_id) + pb_var(2, APP_VERSION)
    third_app = pb_len(1, meta.ticket)
    request = pb_len(1, app_base)
    request += pb_len(3, third_app)
    request += pb_var(4, 4)
    request += pb_len(6, b"")
    request += pb_var(7, 0)
    request += pb_var(8, 6)
    return request


def _manual_auth_head(device_id: bytes) -> bytes:
    ints = [
        (1, 1), (2, 0), (3, 0), (4, 0), (5, CLIENT_VERSION), (6, 11),
        (7, 0), (8, 0), (9, 0), (10, 1), (11, 0), (12, 0),
        (13, 0), (17, 0), (18, 1), (20, 1504), (21, 0), (22, 0),
        (23, 0), (25, 17), (26, 4), (28, 1), (29, 1), (30, 0),
    ]
    return wpkg_head(ints, [(14, b""), (24, device_id), (27, b"")])


def _hybrid_ecdh_encrypt(plaintext: bytes, server_public_key: bytes
                         ) -> tuple[EcdhKey, bytes, bytes, bytes]:
    """混合 ECDH 加密（secret=SHA256(ECDH)，CEK 随机，双层 AES-GCM）。

    返回 (ephemeral, okm, compressed_body, encrypted)。
    """
    ephemeral = EcdhKey()
    ephemeral.generate()
    ephemeral_pub = ephemeral.public_key()
    shared = ephemeral.raw_shared(server_public_key)
    secret = sha256(shared)
    # hash1 = SHA256("1" || "415" || ephemeralPub)
    hash1_input = b"1" + b"415" + ephemeral_pub
    hash1 = sha256(hash1_input)
    cek = os.urandom(32)
    secret_key = secret[0:24]
    encrypted_key, _iv = gcm_encrypt_layout(secret_key, hash1, cek)
    prk = hkdf_extract(b"security hdkf expand", cek)
    okm = hkdf_expand(prk, hash1, 56)
    # hash2 = SHA256("1" || "415" || ephemeralPub || encryptedKey)
    hash2 = sha256(hash1_input + encrypted_key)
    compressed = lz4_all_literal(plaintext)
    okm_key = okm[0:24]
    encrypted_body, _iv2 = gcm_encrypt_layout(okm_key, hash2, compressed)
    ecdh_key = pb_var(1, 415) + pb_len(2, ephemeral_pub)
    out = bytearray()
    out += pb_var(1, 1)
    out += pb_len(2, ecdh_key)
    out += pb_len(3, encrypted_key)
    out += pb_len(4, b"")
    out += pb_len(5, encrypted_body)
    return ephemeral, okm, compressed, bytes(out)


def build_login_body(login_buffer: str, app_device_id: bytes) -> tuple[bytes, ManualAuthTemp]:
    """构造 ManualAuth 请求体（WPKG 头 + 混合 ECDH 加密体）。"""
    meta = parse_login_buffer(login_buffer)
    request = _build_manual_auth_request(meta, app_device_id)
    ephemeral, okm, comp_body, encrypted = _hybrid_ecdh_encrypt(
        request, manual_auth_server_pub())
    temp = ManualAuthTemp(ephemeral=ephemeral, okm=okm, comp_body=comp_body)
    return _manual_auth_head(meta.device_id) + encrypted, temp


def parse_login_response(body: bytes, temp: ManualAuthTemp) -> bytes:
    """解密 ManualAuth 响应，返回明文 protobuf。"""
    hybrid = None
    try:
        head = decode_wpkg_head(body)
        if head.offset < len(body) and body[head.offset] == 0x0A:
            hybrid = body[head.offset:]
    except ValueError:
        pass
    if hybrid is None:
        marker = bytes([0x08, 0x9F, 0x03, 0x12, 0x41, 0x04])
        for i in range(2, len(body) - len(marker) + 1):
            if body[i:i + len(marker)] == marker:
                hybrid = body[i - 2:]
                break
    if hybrid is None:
        raise ValueError("manual auth response marker not found")
    if temp.ephemeral is None or len(temp.okm) != 56 or not temp.comp_body:
        raise ValueError("manual auth temp state incomplete")

    f1 = pb_get_bytes(hybrid, 1)
    f3 = pb_get_bytes(hybrid, 3)
    if not f1:
        raise ValueError("manual auth response missing field 1")
    if not f3:
        raise ValueError("manual auth response missing field 3")
    server_pub = pb_get_bytes(f1, 2)
    if not server_pub:
        raise ValueError("manual auth response missing server public key")

    credential_type = 1  # 字段缺失时默认 1（与参考实现一致）
    f2 = pb_get(hybrid, 2)
    if f2 is not None:
        if isinstance(f2, bytes):
            raise ValueError("unexpected credential type wire type")
        credential_type = int(f2)

    shared = temp.ephemeral.raw_shared(server_pub)
    secret = sha256(shared)
    # aad = SHA256(okm[24:56] || compBody || "415" || serverPub || str(credentialType))
    aad_input = temp.okm[24:56] + temp.comp_body + b"415" + server_pub
    aad_input += str(credential_type).encode("ascii")
    aad = sha256(aad_input)
    secret_key = secret[0:24]
    compressed = gcm_decrypt_layout(secret_key, aad, f3)
    return lz4_decompress(compressed)


def extract_session(manual_auth_response: bytes) -> AppSession:
    f3 = pb_get_bytes(manual_auth_response, 3)
    if not f3:
        raise ValueError("manual auth response missing field 3")
    session_block = pb_get_bytes(f3, 2)
    identity_block = pb_get_bytes(f3, 3)
    if not session_block:
        raise ValueError("missing session block")
    if not identity_block:
        raise ValueError("missing identity block")

    send_key = pb_get_bytes(session_block, 1)
    recv_key = pb_get_bytes(session_block, 2)
    if not send_key or len(send_key) not in (16, 24, 32):
        raise ValueError("invalid send key")
    if not recv_key or len(recv_key) not in (16, 24, 32):
        raise ValueError("invalid recv key")
    uin = pb_get(identity_block, 1)
    if isinstance(uin, bytes) or uin is None or int(uin) <= 0:
        raise ValueError("invalid uin")

    f9 = pb_get(session_block, 9)
    ticket = pb_get(session_block, 12)
    out = AppSession()
    out.send_key = send_key
    out.recv_key = recv_key
    out.f9 = f9 if isinstance(f9, bytes) else b""
    out.ticket = ticket if isinstance(ticket, bytes) else b""
    out.uin = int(uin)
    out.device_id = ILINK_DEVICE.encode("ascii")
    return out


# ---- js-login ----

def _session_info(uin: int, platform: str, session_device: bytes) -> bytes:
    uin32 = uin & 0xFFFFFFFF
    out = pb_len(1, SESSION_KEY_LITERAL.encode("ascii"))
    out += pb_var(2, uin32)
    out += pb_len(3, session_device)
    out += pb_var(4, SESSION_CLIENT_VERSION)
    out += pb_len(5, platform.encode("ascii"))
    out += pb_var(6, 0)
    return out


def _session_wpkg_head(uin: int, f9: bytes, device_id: bytes) -> bytes:
    dev = device_id if device_id else ILINK_DEVICE.encode("ascii")
    ints = [
        (1, 1), (2, uin), (3, 0), (4, 0), (5, CLIENT_VERSION), (6, 11),
        (7, 0), (8, 0), (9, 0), (10, 1), (11, 0), (12, 0),
        (13, 0), (17, 0), (18, 1), (20, 1504), (21, 0), (22, uin),
        (23, 0), (25, 16), (26, 4), (28, 1), (29, 1), (30, 0),
    ]
    return wpkg_head(ints, [(14, b""), (24, dev), (27, f9)])


def _random_session_device() -> bytes:
    mac = bytearray(os.urandom(6))
    mac[0] = (mac[0] | 0x02) & 0xFE
    return ("%02X-%02X-%02X-%02X-%02X-%02X" % tuple(mac)).encode("ascii")


def build_jsapi_plaintext(uin: int, app_id: str, url: bytes, cmd: int,
                          host_app_id: bytes, session_device: bytes) -> bytes:
    real_url = url if url else JS_LOGIN_URL.encode("ascii")
    if cmd == 0:
        cmd = JS_LOGIN_CMD_ID
    host = host_app_id if host_app_id else HOST_APP_ID_DEFAULT.encode("ascii")
    device = session_device if session_device else _random_session_device()
    app_id_bytes = app_id.encode("ascii")

    body = pb_len(1, _session_info(uin, UNIFIED_PC_WINDOWS, device))
    body += pb_len(2, app_id_bytes)
    body += pb_var(4, 1)
    body += pb_len(5, b"")
    body += pb_len(6, b"")
    body += pb_var(7, 1)

    out = bytearray()
    out += pb_len(1, _session_info(uin, WINDOWS_NAME, device))
    out += pb_len(2, real_url)
    out += pb_len(3, host)
    out += pb_var(4, 5)
    out += pb_len(5, body)
    out += pb_len(6, app_id_bytes)
    out += pb_var(7, cmd)
    out += pb_var(8, 1610627409)
    out += pb_len(9, WINDOWS_PLUGIN.encode("ascii"))
    out += pb_var(10, 573651281)
    return bytes(out)


def build_transfer_packet(session: AppSession, plaintext: bytes) -> bytes:
    compressed = lz4_all_literal(plaintext)
    encrypted, _iv = gcm_encrypt_layout(session.send_key, b"", compressed)
    head = _session_wpkg_head(session.uin, session.f9, session.device_id) + encrypted
    shortlink = build_shortlink(TRANSFER_CMD, 0, head)
    url = TRANSFER_URL.encode("ascii")
    host = TRANSFER_HOST.encode("ascii")
    envelope = bytearray()
    envelope += u16be(len(url)) + url
    envelope += u16be(len(host)) + host
    envelope += u32be(len(shortlink)) + shortlink
    return u32be(len(envelope)) + bytes(envelope)


def session_decrypt(body: bytes, recv_key: bytes) -> bytes:
    """候选偏移：WPKG 头尾 + 前 220 字节逐个尝试（与参考实现一致的探测策略）。"""
    offsets: list[int] = []
    try:
        offsets.append(decode_wpkg_head(body).offset)
    except ValueError:
        pass
    offsets.extend(range(min(220, len(body))))
    for offset in offsets:
        if len(body) - offset < 29:
            continue
        blob = body[offset:]
        try:
            compressed = gcm_decrypt_layout(recv_key, b"", blob)
            return lz4_decompress(compressed)
        except Exception:
            continue
    raise ValueError("session decrypt failed for all candidate offsets")


def extract_code(response: bytes) -> bytes:
    nested = pb_get_bytes(response, 2)
    if not nested:
        raise ValueError("js-login response missing field 2")
    code = pb_get_bytes(nested, 3)
    if not code:
        raise ValueError("js-login response missing code field")
    return code
