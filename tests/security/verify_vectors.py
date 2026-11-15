#!/usr/bin/env python3
"""Independent verification of the Keyvora vault format v1 (QA / Security).

Re-implements docs/VAULT_FORMAT.md from scratch in Python with *different* cryptographic libraries
(argon2-cffi = reference C implementation of Argon2; `cryptography` = OpenSSL AES-GCM and HKDF) and checks that
the vectors produced by the Rust core (packages/shared-models/test-vectors/vault-v1.json) decrypt to the expected
entries. A pass means: the spec is implementable as written, and the Rust implementation follows it.

Usage:  python -m venv .venv && .venv/bin/pip install argon2-cffi cryptography
        python tests/security/verify_vectors.py [path/to/vault-v1.json]
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
import unicodedata
import uuid
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parents[2]
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def argon2id(password: bytes, salt: bytes, m: int, t: int, p: int) -> bytes:
    return hash_secret_raw(secret=password, salt=salt, time_cost=t, memory_cost=m, parallelism=p, hash_len=32, type=Type.ID, version=19)


def hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def kdf_canon(kdf: dict) -> str:
    if kdf["algorithm"] == "argon2id":
        return f"argon2id$v=19$m={kdf['memoryKiB']}$t={kdf['iterations']}$p={kdf['parallelism']}$salt={kdf['salt']}"
    if kdf["algorithm"] == "hkdf-sha256":
        return f"hkdf-sha256$salt={kdf['salt']}"
    raise ValueError("unknown kdf")


def slot_aad(vault_id: uuid.UUID, slot: dict) -> bytes:
    return b"keyvora.vault.v1.slot\x00" + vault_id.bytes + slot["slotId"].encode() + b"\x00" + kdf_canon(slot["kdf"]).encode()


def payload_aad(c: dict) -> bytes:
    digest_input = b""
    for s in c["keySlots"]:
        digest_input += s["slotId"].encode() + b"\x00" + kdf_canon(s["kdf"]).encode() + b"\x00"
        digest_input += s["wrap"]["nonce"].encode() + b"\x00" + s["wrap"]["ciphertext"].encode() + b"\x00"
    return (
        b"keyvora.vault.v1.payload\x00"
        + struct.pack(">I", c["formatVersion"])
        + uuid.UUID(c["vaultId"]).bytes
        + struct.pack(">Q", c["revision"])
        + struct.pack(">Q", c["keyringRevision"])
        + hashlib.sha256(digest_input).digest()
    )


def aead_open(key: bytes, sealed: dict, aad: bytes) -> bytes:
    assert sealed["algorithm"] == "A256GCM"
    return AESGCM(key).decrypt(base64.b64decode(sealed["nonce"]), base64.b64decode(sealed["ciphertext"]), aad)


def parse_recovery(s: str) -> bytes:
    norm = "".join({"0": "O", "1": "I", "8": "B"}.get(ch, ch.upper()) for ch in s if ch not in " -\t\r\n")
    assert len(norm) == 56, "recovery key length"
    bits = "".join(f"{B32.index(ch):05b}" for ch in norm)
    raw = bytes(int(bits[i : i + 8], 2) for i in range(0, 280, 8))
    key, check = raw[:32], raw[32:]
    assert hashlib.sha256(key).digest()[:3] == check, "recovery checksum"
    return key


def open_container(c: dict, *, master: str | None = None, recovery: str | None = None) -> list[dict]:
    assert c["format"] == "keyvora.vault" and c["formatVersion"] == 1
    vid = uuid.UUID(c["vaultId"])
    if master is not None:
        slot = c["keySlots"][0]
        k = slot["kdf"]
        kek = argon2id(unicodedata.normalize("NFC", master).encode(), base64.b64decode(k["salt"]), k["memoryKiB"], k["iterations"], k["parallelism"])
    else:
        slot = c["keySlots"][1]
        kek = hkdf(parse_recovery(recovery), base64.b64decode(slot["kdf"]["salt"]), b"keyvora.vault.v1.recovery-kek")
    dek = aead_open(kek, slot["wrap"], slot_aad(vid, slot))
    assert len(dek) == 32
    payload = json.loads(aead_open(dek, c["payload"], payload_aad(c)))
    assert payload["schemaVersion"] == 1
    entries = []
    for rec in payload["records"]:
        live = [v for v in rec["versions"] if not v["deleted"]]
        if not live:
            continue  # deleted record (tombstone)
        main = max(live, key=lambda v: (v["updatedAt"], v["dot"]["device"], v["dot"]["counter"]))
        for v in rec["versions"]:
            assert rec["context"].get(v["dot"]["device"], 0) >= v["dot"]["counter"], "dot not covered by context"
        entries.append({k: main[k] for k in ("title", "username", "password", "urls", "notes")})
    return entries


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "packages/shared-models/test-vectors/vault-v1.json"
    v = json.loads(path.read_text(encoding="utf-8"))
    checks = 0

    a = v["argon2id"]
    got = argon2id(a["passwordUtf8"].encode(), bytes.fromhex(a["saltHex"]), a["memoryKiB"], a["iterations"], a["parallelism"])
    assert got.hex() == a["expectedKeyHex"], "argon2id vector"
    checks += 1

    h = v["hkdfRecovery"]
    assert hkdf(bytes.fromhex(h["ikmHex"]), bytes.fromhex(h["saltHex"]), h["info"].encode()).hex() == h["expectedKeyHex"], "hkdf vector"
    checks += 1

    g = v["aes256gcm"]
    ct = AESGCM(bytes.fromhex(g["keyHex"])).encrypt(bytes.fromhex(g["nonceHex"]), bytes.fromhex(g["plaintextHex"]), bytes.fromhex(g["aadHex"]))
    assert ct.hex() == g["expectedCiphertextHex"], "aes-gcm vector"
    checks += 1

    vault = v["vault"]
    c = json.loads(vault["container"])
    key = lambda e: e["title"]  # noqa: E731
    expected = sorted(vault["expectedEntries"], key=key)
    for kwargs in ({"master": vault["masterPassword"]}, {"master": vault["masterPasswordNfdVariant"]}, {"recovery": vault["recoveryKey"]}):
        assert sorted(open_container(c, **kwargs), key=key) == expected, f"container via {list(kwargs)}"
        checks += 1

    # Negative checks: tampering must fail authentication.
    tampered = json.loads(vault["container"])
    tampered["revision"] += 1
    try:
        open_container(tampered, master=vault["masterPassword"])
        raise AssertionError("tampered revision accepted")
    except Exception as e:  # cryptography raises InvalidTag
        assert type(e).__name__ == "InvalidTag", e
    checks += 1
    try:
        open_container(c, master=vault["masterPassword"] + "x")
        raise AssertionError("wrong password accepted")
    except Exception as e:
        assert type(e).__name__ == "InvalidTag", e
    checks += 1

    print(f"OK: {checks} independent checks passed for {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
