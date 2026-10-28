"""MMTLS / YYB 协议所需的密码学与编码基础件。

移植自 UESTC-MoonCheck 的 firmware/src/wx_crypto.cpp（其本身移植自
moon-uestc 的 _wechat_crypto.py / _wechat_wire.py，与 YYB-Go-Enhanced
的 Go 参考逐字节一致）。

与原实现的差异：原版需要自写 AES-192-GCM 以绕过 Arduino mbedtls 的
硬件密钥长度限制，Python 的 cryptography 原生支持，故此处直接复用。
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ==== 十六进制 / 追加辅助 ====

def from_hex(text: str) -> bytes:
    text = text.strip()
    if len(text) % 2 != 0:
        raise ValueError("hex string must have even length")
    return bytes.fromhex(text)


def to_hex(data: bytes) -> str:
    return data.hex()


def u8(value: int) -> bytes:
    return bytes([value & 0xFF])


def u16be(value: int) -> bytes:
    return (value & 0xFFFF).to_bytes(2, "big")


def u32be(value: int) -> bytes:
    return (value & 0xFFFFFFFF).to_bytes(4, "big")


def u64be(value: int) -> bytes:
    return (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")


# ==== varint / protobuf ====

def encode_varint(value: int) -> bytes:
    if value < 0:
        value &= 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """返回 (value, new_offset)；格式非法时抛 ValueError。"""
    value = 0
    for index in range(10):
        if offset >= len(data):
            raise ValueError("truncated varint")
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise ValueError("varint overflow")
        value |= (byte & 0x7F) << (index * 7)
        if byte < 0x80:
            return value, offset
    raise ValueError("varint too long")


def pb_len(field: int, data: bytes) -> bytes:
    return encode_varint((field << 3) | 2) + encode_varint(len(data)) + data


def pb_var(field: int, value: int) -> bytes:
    return encode_varint(field << 3) + encode_varint(value)


# protobuf 字段三元组：(field, wire_type, value)
#   wire 0 -> int；wire 1/2/5 -> bytes
PbField = tuple[int, int, "int | bytes"]


def pb_fields(data: bytes) -> list[PbField]:
    """解析一段 protobuf 消息；仅支持 wire type 0/1/2/5。"""
    out: list[PbField] = []
    offset = 0
    length = len(data)
    while offset < length:
        tag, offset = read_varint(data, offset)
        field = tag >> 3
        wire = tag & 7
        if field == 0 or field > ((1 << 29) - 1):
            raise ValueError("invalid protobuf field")
        if wire == 0:
            value, offset = read_varint(data, offset)
        elif wire == 1:
            if offset + 8 > length:
                raise ValueError("truncated fixed64")
            value = data[offset:offset + 8]
            offset += 8
        elif wire == 2:
            size, offset = read_varint(data, offset)
            if size > length - offset:
                raise ValueError("truncated length-delimited field")
            value = data[offset:offset + size]
            offset += size
        elif wire == 5:
            if offset + 4 > length:
                raise ValueError("truncated fixed32")
            value = data[offset:offset + 4]
            offset += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        out.append((field, wire, value))
    return out


def pb_get(data: bytes, field: int):
    """取指定字段的值（同号字段取最后一个，与参考实现一致）；缺失返回 None。"""
    found = None
    for f, _wire, value in pb_fields(data):
        if f == field:
            found = value
    return found


def pb_get_bytes(data: bytes, field: int) -> bytes | None:
    value = pb_get(data, field)
    return value if isinstance(value, bytes) else None


# ==== LZ4 block ====

def lz4_all_literal(data: bytes) -> bytes:
    """LZ4 全字面量压缩（单序列、无匹配；协议请求侧固定使用）。"""
    length = len(data)
    out = bytearray()
    if length < 15:
        out.append(length << 4)
    else:
        out.append(0xF0)
        remaining = length - 15
        while remaining >= 255:
            out.append(255)
            remaining -= 255
        out.append(remaining)
    out += data
    return bytes(out)


def lz4_decompress(data: bytes, max_output: int = 256 * 1024) -> bytes:
    """LZ4 block 解码；越界或超限抛 ValueError。"""
    out = bytearray()
    offset = 0
    length = len(data)
    while offset < length:
        token = data[offset]
        offset += 1
        literal_length = token >> 4
        if literal_length == 15:
            while True:
                if offset >= length:
                    raise ValueError("truncated LZ4 literal length")
                extra = data[offset]
                offset += 1
                literal_length += extra
                if extra != 255:
                    break
        if literal_length > length - offset:
            raise ValueError("LZ4 literal overruns input")
        if len(out) + literal_length > max_output:
            raise ValueError("LZ4 output exceeds limit")
        out += data[offset:offset + literal_length]
        offset += literal_length
        if offset == length:
            break
        if offset + 2 > length:
            raise ValueError("truncated LZ4 match offset")
        match_offset = data[offset] | (data[offset + 1] << 8)
        offset += 2
        if match_offset == 0 or match_offset > len(out):
            raise ValueError("invalid LZ4 match offset")
        match_length = (token & 0x0F) + 4
        if (token & 0x0F) == 15:
            while True:
                if offset >= length:
                    raise ValueError("truncated LZ4 match length")
                extra = data[offset]
                offset += 1
                match_length += extra
                if extra != 255:
                    break
        if len(out) + match_length > max_output:
            raise ValueError("LZ4 output exceeds limit")
        start = len(out) - match_offset
        for i in range(match_length):
            out.append(out[start + i])
    return bytes(out)


# ==== 哈希 / HMAC / HKDF ====

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac_sha256(prk, previous + info + bytes([counter]))
        output += previous
        counter += 1
    return bytes(output[:length])


def expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    """expand_label(secret, label, ctx, n) = HKDF-Expand(secret, label||ctx, n)。"""
    return hkdf_expand(secret, label.encode("ascii") + context, length)


def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


# ==== AES-GCM ====

def aes_gcm_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """返回 ciphertext || tag（与 mbedtls 输出一致）。"""
    if len(nonce) != 12:
        raise ValueError("GCM nonce must be 12 bytes")
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes, nonce: bytes, aad: bytes, wire: bytes) -> bytes:
    """入参为 ciphertext || tag。"""
    if len(nonce) != 12:
        raise ValueError("GCM nonce must be 12 bytes")
    return AESGCM(key).decrypt(nonce, wire, aad)


def gcm_encrypt_layout(key: bytes, aad: bytes, plaintext: bytes,
                       iv: bytes | None = None) -> tuple[bytes, bytes]:
    """YYB blob 布局加密：ciphertext || IV(12) || tag(16)。返回 (blob, iv)。"""
    nonce = iv if iv is not None else os.urandom(12)
    wire = aes_gcm_encrypt(key, nonce, aad, plaintext)
    return wire[:-16] + nonce + wire[-16:], nonce


def gcm_decrypt_layout(key: bytes, aad: bytes, blob: bytes) -> bytes:
    """YYB blob 布局解密：入参 ciphertext || IV(12) || tag(16)。"""
    if len(blob) < 12 + 16:
        raise ValueError("blob shorter than IV + tag")
    cipher_len = len(blob) - 12 - 16
    nonce = blob[cipher_len:cipher_len + 12]
    wire = blob[:cipher_len] + blob[cipher_len + 12:]
    return aes_gcm_decrypt(key, nonce, aad, wire)


# ==== ECDH P-256 ====

class EcdhKey:
    """一次性 ECDH 密钥对（P-256）。"""

    def __init__(self) -> None:
        self._private = None

    def generate(self) -> None:
        self._private = ec.generate_private_key(ec.SECP256R1())

    def load_private(self, scalar: bytes) -> None:
        self._private = ec.derive_private_key(
            int.from_bytes(scalar, "big"), ec.SECP256R1())

    def public_key(self) -> bytes:
        """SEC1 未压缩公钥（65 字节）。"""
        return self._private.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    def raw_shared(self, peer_public: bytes) -> bytes:
        """原始 ECDH 共享 X 坐标（32 字节大端）。"""
        if len(peer_public) != 65:
            raise ValueError("peer public key must be 65 bytes")
        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), peer_public)
        return self._private.exchange(ec.ECDH(), peer)

    def mmtls_secret(self, peer_public: bytes) -> bytes:
        """MMTLS secret = SHA256(ECDH 共享 X 坐标)。"""
        return sha256(self.raw_shared(peer_public))
