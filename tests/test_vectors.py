"""黄金向量对拍测试。

向量来源：UESTC-MoonCheck 的 firmware/include/golden_vectors.h 与
aesgcm_vectors.h（由 gen_golden_vectors.py 从 moon-uestc Python 参考实现
生成，并与 YYB-Go-Enhanced 的 Go 参考逐字节一致）。

这些测试不需要任何真实账号或网络，是移植正确性的主要保障。
"""
from __future__ import annotations

import unittest

from uestc_wx import wire
from uestc_wx.crypto import (
    EcdhKey,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    from_hex,
    gcm_decrypt_layout,
    gcm_encrypt_layout,
    lz4_all_literal,
    lz4_decompress,
    sha256,
    to_hex,
)

# ---- 与 gen_golden_vectors.py 完全一致的固定输入 ----

K32 = bytes(range(32))
K16 = bytes(range(16))
IV12 = bytes(range(12))


def make_rand32() -> bytes:
    return bytes((i * 7) % 256 for i in range(32))


def make_pub1() -> bytes:
    return (bytes([0x04])
            + bytes((i * 3) % 256 for i in range(32))
            + bytes((i * 5) % 256 for i in range(32)))


def make_pub2() -> bytes:
    return bytes([0x05]) + bytes((i * 11) % 256 for i in range(64))


# ---- 黄金向量（对应 golden_vectors.h） ----

CLIENT_HELLO = (
    "000000d00103f101c02b00070e151c232a31383f464d545b626970777e858c93"
    "9aa1a8afb6bdc4cbd2d967e8f109000000a2010000009d001002000000470000"
    "0001004104000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e"
    "5154575a5d00050a0f14191e23282d32373c41464b50555a5f64696e73787d82"
    "878c91969b0000004700000002004105000b16212c37424d58636e79848f9aa5"
    "b0bbc6d1dce7f2fd08131e29343f4a55606b76818c97a2adb8c3ced9e4effa05"
    "101b26313c47525d68737e89949faab500000001"
)

PSK_CLIENT_HELLO = (
    "000000580103f10100a800070e151c232a31383f464d545b626970777e858c93"
    "9aa1a8afb6bdc4cbd2d967e8f1090000002a0100000025000f010000001e5449"
    "434b45545449434b45545449434b45545449434b45545449434b4554"
)

RECORD_CRYPT = "92a73f9d70e79c25d0b2475f8bed0677aa5da9a83fbb484d8ede51e146"
MASTER = "03d549a133b334ee93121563a010f2ecef64b2cd9a93597d4e6cc32e66d70655"
HANDSHAKE_KEYS = (
    "14af4aecbdd965ca95dc8506f79fc6c9e01cc61a140a58eb31e4ab10a9248d3a"
    "9d882ab3125bcdbf5f24955ee65b2e48a57333fb26dac6d6"
)
APP_KEYS = (
    "0503d5d1e64841db200d7e1baaf4bc7e4b7434cf64f2af9d75d6a0baecb09e28"
    "8713a98602b961170f5c90ad94bfea949d5470912e068e22"
)
FINISHED_CLIENT = "476f20f2e48529d0c6a683e577babc8e811d4375d81c8fa6b335a6861c3b815c"
FINISHED_SERVER = "177245d42748651e740d352246680cb363af3c6af62cc80d5ee7ee2c80869b97"
PSK_ONEWAY = "e72334990b4d59b91ad228d6886a03dcbfc1d1aa5ba1dad2fc4aa06b"
WPKG_ROUNDTRIP = (
    "01010102959aef3a0300040005818220060b0700080009000a010b000c000d00"
    "1100120114e00b150016959aef3a170019101a041c011d011e00000e00180664"
    "65766963651b026639004a"
)
LZ4_SHORT = "5068656c6c6f"
LZ4_LONG = (
    "f031000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d"
    "1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d"
    "3e3f"
)
JSAPI = (
    "0a350a0a73657373696f6e6b657910959aef3a1a1141412d42422d43432d4444"
    "2d45452d464620ff8d9c98062a0757696e646f77733000121b2f6367692d6269"
    "6e2f6d6d62697a2d62696e2f6a732d6c6f67696e1a1277786434343937373332"
    "386233366536343720052a5c0a3e0a0a73657373696f6e6b657910959aef3a1a"
    "1141412d42422d43432d44442d45452d464620ff8d9c98062a10556e69666965"
    "64504357696e646f777330001212777861613738626632393035663031636565"
    "20012a0032003801321277786161373862663239303566303163656538850840"
    "d1f28080064a1157696e646f777378576562506c7567696e50d1f2c49102"
)
SHORTLINK = "0000001d1110076d00000b41000000077061796c6f61642d6279746573"
RECORD_FRAME = "16f1030003010203"
TRANSFER_PLAIN = (
    "0a320a0a73657373696f6e6b6579102a1a1141412d42422d43432d44442d4545"
    "2d464620ff8d9c98062a0757696e646f77733000121b2f6367692d62696e2f6d"
    "6d62697a2d62696e2f6a732d6c6f67696e1a1277786434343937373332386233"
    "366536343720052a590a3b0a0a73657373696f6e6b6579102a1a1141412d4242"
    "2d43432d44442d45452d464620ff8d9c98062a10556e6966696564504357696e"
    "646f77733000121277786161373862663239303566303163656520012a003200"
    "3801321277786161373862663239303566303163656538850840d1f28080064a"
    "1157696e646f777378576562506c7567696e50d1f2c49102"
)

# ---- AES-192-GCM 向量（aesgcm_vectors.h） ----
GCM_V1 = ("8e9c4ef7f699a46fbe46bdeedfc8a904664d395fd34c73bc9c2e05ef0d892d2c"
          "4b")
GCM_V2 = ("9e815ae3e1c1b176a84ba4fa87d1a40876e74b7340d92ec607271340b5ee5924"
          "aff3acfb45e0af079cdecc2a93c231fc49")
GCM_V3 = "6d57085841697181e92cc746114ee785"


class CryptoVectors(unittest.TestCase):
    """crypto 层基础件。"""

    def test_varint_roundtrip(self):
        from uestc_wx.crypto import encode_varint, read_varint
        for value in (0, 1, 127, 128, 300, 16383, 16384, 2**32, 2**53):
            encoded = encode_varint(value)
            decoded, offset = read_varint(encoded, 0)
            self.assertEqual(decoded, value, f"varint {value}")
            self.assertEqual(offset, len(encoded))

    def test_lz4_short(self):
        self.assertEqual(to_hex(lz4_all_literal(b"hello")), LZ4_SHORT)

    def test_lz4_long(self):
        self.assertEqual(to_hex(lz4_all_literal(bytes(range(64)))), LZ4_LONG)

    def test_lz4_decompress(self):
        back = lz4_decompress(from_hex(LZ4_LONG))
        self.assertEqual(back, bytes(range(64)))

    def test_lz4_roundtrip_various(self):
        for size in (0, 1, 14, 15, 16, 254, 255, 256, 1000):
            data = bytes((i * 7) % 256 for i in range(size))
            self.assertEqual(lz4_decompress(lz4_all_literal(data)), data,
                             f"size {size}")

    def test_gcm192_vectors(self):
        key = bytes(range(24))
        nonce = bytes(range(12))
        aad1 = b"aad-1"
        pt1 = b"hello manual auth"
        self.assertEqual(to_hex(aes_gcm_encrypt(key, nonce, aad1, pt1)), GCM_V1)
        self.assertEqual(aes_gcm_decrypt(key, nonce, aad1, from_hex(GCM_V1)), pt1)

        pt2 = b"x" * 33
        self.assertEqual(to_hex(aes_gcm_encrypt(key, nonce, b"", pt2)), GCM_V2)

        aad3 = b"only-aad"
        self.assertEqual(to_hex(aes_gcm_encrypt(key, nonce, aad3, b"")), GCM_V3)

    def test_gcm192_tamper_rejected(self):
        from cryptography.exceptions import InvalidTag
        key = bytes(range(24))
        nonce = bytes(range(12))
        bad = bytearray(from_hex(GCM_V1))
        bad[-1] ^= 1
        with self.assertRaises(InvalidTag):
            aes_gcm_decrypt(key, nonce, b"aad-1", bytes(bad))

    def test_gcm_layout_roundtrip(self):
        key = bytes(range(16))
        aad = b"ctx"
        plaintext = b"payload bytes here"
        blob, iv = gcm_encrypt_layout(key, aad, plaintext)
        self.assertEqual(len(iv), 12)
        self.assertEqual(len(blob), len(plaintext) + 12 + 16)
        self.assertEqual(gcm_decrypt_layout(key, aad, blob), plaintext)

    def test_ecdh_p256(self):
        a, b = EcdhKey(), EcdhKey()
        a.generate()
        b.generate()
        self.assertEqual(len(a.public_key()), 65)
        self.assertEqual(a.raw_shared(b.public_key()), b.raw_shared(a.public_key()))
        self.assertEqual(a.mmtls_secret(b.public_key()),
                         sha256(a.raw_shared(b.public_key())))


class WireVectors(unittest.TestCase):
    """wire 层协议编解码。"""

    def setUp(self):
        self.r32 = make_rand32()
        self.pub1 = make_pub1()
        self.pub2 = make_pub2()

    def test_client_hello(self):
        actual = wire.build_client_hello(self.r32, 0x67E8F109, self.pub1, self.pub2)
        self.assertEqual(to_hex(actual), CLIENT_HELLO)

    def test_psk_client_hello(self):
        ticket = bytes(b"TICKET"[i % 6] for i in range(30))
        actual = wire.build_psk_client_hello(self.r32, 0x67E8F109, ticket)
        self.assertEqual(to_hex(actual), PSK_CLIENT_HELLO)

    def test_record_crypt(self):
        actual = wire.encrypt_record_payload(
            K16, IV12, 4, wire.CT_APP_DATA, b"server flight")
        self.assertEqual(to_hex(actual), RECORD_CRYPT)

    def test_record_crypt_roundtrip(self):
        plaintext = b"server flight"
        ct = wire.encrypt_record_payload(K16, IV12, 4, wire.CT_APP_DATA, plaintext)
        back = wire.decrypt_record_payload(K16, IV12, 4, wire.CT_APP_DATA, ct)
        self.assertEqual(back, plaintext)

    def test_master(self):
        self.assertEqual(to_hex(wire.derive_master(K32, self.r32)), MASTER)

    def test_handshake_keys(self):
        keys = wire.derive_handshake_keys(K32, self.r32)
        actual = keys.client_key + keys.server_key + keys.client_iv + keys.server_iv
        self.assertEqual(to_hex(actual), HANDSHAKE_KEYS)

    def test_app_keys(self):
        keys = wire.derive_app_keys(K32, self.r32)
        actual = keys.client_key + keys.server_key + keys.client_iv + keys.server_iv
        self.assertEqual(to_hex(actual), APP_KEYS)

    def test_finished_client(self):
        actual = wire.finished_verify_data(K32, True, self.r32)
        self.assertEqual(to_hex(actual), FINISHED_CLIENT)

    def test_finished_server(self):
        actual = wire.finished_verify_data(K32, False, self.r32)
        self.assertEqual(to_hex(actual), FINISHED_SERVER)

    def test_psk_oneway(self):
        keys = wire.derive_psk_one_way_keys(K32, wire.EARLY_KEYS_LABEL, self.r32)
        self.assertEqual(to_hex(keys.key + keys.iv), PSK_ONEWAY)

    def test_wpkg_roundtrip(self):
        upstream = from_hex(
            "01010102959aef3a0300040005818220060b0700080009000a010b000c000d00"
            "1100120114e00b150016959aef3a170019101a041c011d011e00000e001806"
            "6465766963651b026639004a")
        head = wire.decode_wpkg_head(upstream)
        rebuilt = wire.wpkg_head(head.ints, head.byts)
        self.assertEqual(to_hex(rebuilt), WPKG_ROUNDTRIP)

    def test_wpkg_field24(self):
        upstream = from_hex(
            "01010102959aef3a0300040005818220060b0700080009000a010b000c000d00"
            "1100120114e00b150016959aef3a170019101a041c011d011e00000e001806"
            "6465766963651b026639004a")
        head = wire.decode_wpkg_head(upstream)
        values = {field_no: value for field_no, value in head.byts}
        self.assertEqual(values.get(24), b"device")

    def test_jsapi_plaintext(self):
        mac = b"AA-BB-CC-DD-EE-FF"
        url = b"/cgi-bin/mmbiz-bin/js-login"
        host = b"wxd44977328b36e647"
        actual = wire.build_jsapi_plaintext(
            123456789, "wxaa78bf2905f01cee", url, wire.JS_LOGIN_CMD_ID, host, mac)
        self.assertEqual(to_hex(actual), JSAPI)

    def test_shortlink(self):
        actual = wire.build_shortlink(wire.TRANSFER_CMD, 7, b"payload-bytes")
        self.assertEqual(to_hex(actual), SHORTLINK)

    def test_shortlink_roundtrip(self):
        packet = wire.build_shortlink(wire.TRANSFER_CMD, 7, b"payload-bytes")
        parsed = wire.parse_shortlink(packet)
        self.assertEqual(parsed.total_len, len(packet))
        self.assertEqual(parsed.magic, wire.SHORTLINK_MAGIC)
        self.assertEqual(parsed.cmd, wire.TRANSFER_CMD)
        self.assertEqual(parsed.seq, 7)
        self.assertEqual(parsed.body, b"payload-bytes")

    def test_record_frame(self):
        actual = wire.build_record(wire.CT_HANDSHAKE, bytes([0x01, 0x02, 0x03]))
        self.assertEqual(to_hex(actual), RECORD_FRAME)

    def test_record_frame_roundtrip(self):
        frame = wire.build_record(wire.CT_HANDSHAKE, b"\x01\x02\x03")
        records, consumed = wire.parse_records(frame)
        self.assertEqual(consumed, len(frame))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].content_type, wire.CT_HANDSHAKE)
        self.assertEqual(records[0].payload, b"\x01\x02\x03")

    def test_parse_records_partial(self):
        """不完整尾部不应被消费。"""
        frame = wire.build_record(wire.CT_HANDSHAKE, b"\x01\x02\x03")
        records, consumed = wire.parse_records(frame[:-1])
        self.assertEqual(records, [])
        self.assertEqual(consumed, 0)

    def test_transfer_plaintext(self):
        mac = b"AA-BB-CC-DD-EE-FF"
        host = b"wxd44977328b36e647"
        actual = wire.build_jsapi_plaintext(
            42, "wxaa78bf2905f01cee", b"", 0, host, mac)
        self.assertEqual(to_hex(actual), TRANSFER_PLAIN)

    def test_transfer_roundtrip(self):
        session = wire.AppSession()
        session.send_key = K16
        session.recv_key = bytes(range(16, 32))
        session.f9 = b"\xf9" * 8
        session.uin = 42

        mac = b"AA-BB-CC-DD-EE-FF"
        host = b"wxd44977328b36e647"
        plaintext = wire.build_jsapi_plaintext(
            42, "wxaa78bf2905f01cee", b"", 0, host, mac)
        envelope = wire.build_transfer_packet(session, plaintext)

        # 解析信封：4B len + 2B urllen + url + 2B hostlen + host + 4B slen + shortlink
        inner = envelope[4:]
        url_len = (inner[0] << 8) | inner[1]
        pos = 2 + url_len
        host_len = (inner[pos] << 8) | inner[pos + 1]
        pos += 2 + host_len
        sl_len = int.from_bytes(inner[pos:pos + 4], "big")
        pos += 4
        shortlink_bytes = inner[pos:pos + sl_len]

        packet = wire.parse_shortlink(shortlink_bytes)
        decrypted = wire.session_decrypt(packet.body, session.send_key)
        self.assertEqual(decrypted, plaintext)

    def test_session_decrypt_all_offsets_fail(self):
        with self.assertRaises(ValueError):
            wire.session_decrypt(b"\x00" * 64, K16)


class HandshakeVectors(unittest.TestCase):
    """握手相关编解码。"""

    def test_handshake_roundtrip(self):
        body = b"\xaa" * 32
        payload = wire.build_handshake(wire.HS_FINISHED, body)
        message_type, parsed = wire.split_handshake(payload)
        self.assertEqual(message_type, wire.HS_FINISHED)
        self.assertEqual(parsed, body)

    def test_finished_roundtrip(self):
        verify = bytes(range(32))
        payload = wire.build_finished(verify)
        message_type, body = wire.split_handshake(payload)
        self.assertEqual(message_type, wire.HS_FINISHED)
        self.assertEqual(wire.parse_finished(body), verify)

    def test_new_session_ticket(self):
        entry = bytes([1]) + (3600).to_bytes(4, "big") + b"\xde\xad\xbe\xef"
        body = bytes([1]) + len(entry).to_bytes(4, "big") + entry
        tickets = wire.parse_new_session_ticket(body)
        self.assertEqual(len(tickets), 1)
        self.assertEqual(tickets[0].psk_type, 1)
        self.assertEqual(tickets[0].lifetime, 3600)
        self.assertEqual(tickets[0].ticket_entry, entry)

    def test_server_hello_parse(self):
        # 布局与 C++ parseServerHello 一致：
        # body[0:2] 前缀 → body[2:4] cipher → body[4:36] serverRandom
        # → body[36:40] extLen → body[40:] ext
        server_random = bytes(range(32))
        server_pub = bytes([0x04]) + bytes(range(64))
        # ext[0]=extType, ext[1:5]=扩展数据长度, ext[5:7]=2 字节占位，ext[7:] 起为
        # group(4B BE) + keyLen(2B BE) + key——与 C++ 的 cursor=7 对齐
        inner = (wire.u32be(wire.GROUP_SECP256R1)
                 + (65).to_bytes(2, "big")
                 + server_pub)
        ext = (bytes([wire.EXT_KEY_SHARE])
               + len(inner).to_bytes(4, "big")
               + b"\x00\x00"
               + inner)
        body = (bytes([0x03, 0xF1])                  # body[0:2]
                + wire.u16be(wire.CIPHER_ECDHE)      # body[2:4]
                + server_random                      # body[4:36]
                + len(ext).to_bytes(4, "big")        # body[36:40]
                + ext)
        self.assertEqual(len(server_random), 32)
        hello = wire.parse_server_hello(body)
        self.assertEqual(hello.cipher, wire.CIPHER_ECDHE)
        self.assertEqual(hello.server_random, server_random)
        self.assertEqual(hello.server_group, wire.GROUP_SECP256R1)
        self.assertEqual(hello.server_pub_key, server_pub)


class ProtobufVectors(unittest.TestCase):
    """protobuf 编解码。"""

    def test_pb_roundtrip(self):
        from uestc_wx.crypto import pb_fields, pb_get_bytes, pb_len, pb_var
        msg = pb_var(1, 415) + pb_len(2, b"hello") + pb_var(3, 0)
        fields = pb_fields(msg)
        self.assertEqual(len(fields), 3)
        self.assertEqual(fields[0], (1, 0, 415))
        self.assertEqual(pb_get_bytes(msg, 2), b"hello")
        self.assertEqual(fields[2][2], 0)

    def test_pb_last_wins(self):
        from uestc_wx.crypto import pb_get, pb_var
        msg = pb_var(1, 1) + pb_var(1, 2)
        self.assertEqual(pb_get(msg, 1), 2)

    def test_pb_truncated(self):
        from uestc_wx.crypto import pb_fields
        with self.assertRaises(ValueError):
            pb_fields(b"\x12\x05ab")  # 声明 5 字节，实际只有 2

    def test_manual_auth_server_pub(self):
        pub = wire.manual_auth_server_pub()
        self.assertEqual(len(pub), 65)
        self.assertEqual(pub[0], 0x04)
        # 必须是合法的 P-256 点
        from cryptography.hazmat.primitives.asymmetric import ec
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)


if __name__ == "__main__":
    unittest.main()
