"""Independent vector verification: OpenSSL Argon2/AES + PyCryptodome XChaCha.
Requires cryptography>=44 and pycryptodome. No production secret input.
"""
import hashlib
import hmac
import json
import struct
from pathlib import Path
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import ChaCha20_Poly1305

ROOT = Path(__file__).parent
PASSWORD = "  한글 비밀번호 🔒 e\u0301  ".encode()
PLAINTEXT = b"WithCrypt vector\x00\xff"

def expand(prk, info):
    # RFC 5869 single-block expansion for a 32-byte output.
    return hmac.digest(prk, info + b"\x01", "sha256")

def verify_suite(suite):
    raw = bytes.fromhex((ROOT / f"suite-{suite}.hex").read_text())
    header, salt, prefix = raw[:64], raw[32:48], raw[48:64]
    master = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536).derive(PASSWORD)
    prk = hmac.digest(salt, master, "sha256")
    enc = expand(prk, b"ESB/v1/encryption")
    mac = expand(prk, b"ESB/v1/plaintext-hmac" if suite == 1 else b"ESB/v1/aes-256-gcm/plaintext-hmac")
    pos, data, records = 64, b"", []
    for expected, kind in enumerate([1, 2, 3]):
        r = raw[pos:pos+13]
        rtype, index, length = struct.unpack("<BQI", r)
        assert (rtype, index) == (kind, expected)
        cipher = raw[pos+13:pos+13+length+16]
        aad = b"ESB/v1/record" + header + r
        if suite == 1:
            key, nonce = enc, prefix + struct.pack("<Q", index)
            engine = ChaCha20_Poly1305.new(key=key, nonce=nonce)
            engine.update(aad)
            plain = engine.decrypt_and_verify(cipher[:-16], cipher[-16:])
        else:
            key = expand(prk, b"ESB/v1/aes-256-gcm/record-key" + prefix + struct.pack("<Q", index))
            nonce = prefix[:4] + struct.pack("<Q", index)
            plain = AESGCM(key).decrypt(nonce, cipher, aad)
        if kind == 1:
            assert plain == b"\x08\x00test.bin"
        elif kind == 2:
            data += plain
        else:
            assert struct.unpack("<QQ", plain[:16]) == (len(data), 1)
            assert hmac.compare_digest(plain[16:], hmac.digest(mac, data, "sha256"))
        records.append(dict(index=index, key=key.hex(), nonce=nonce.hex(), aad=aad.hex(), record=(r+cipher).hex(), plaintext=plain.hex()))
        pos += 13 + length + 16
    assert data == PLAINTEXT and pos == len(raw)
    detail = dict(suite=suite, password_utf8=PASSWORD.hex(), plaintext=PLAINTEXT.hex(), header=header.hex(), master=master.hex(), prk=prk.hex(), hmac_key=mac.hex(), original_hmac=hmac.digest(mac,data,"sha256").hex(), records=records, container_sha256=hashlib.sha256(raw).hexdigest())
    (ROOT / f"suite-{suite}.json").write_text(json.dumps(detail, indent=2)+"\n")
    print(f"suite {suite}: independent KDF, keys, AEAD, HMAC and bytes verified")

if __name__ == "__main__":
    for suite in [1, 2]:
        verify_suite(suite)
