#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cookierun_djb.py - Decryptor for Cookie Run (`com.devsisters.CookieRunForKakao`)
`.djb` game-data files (balance tables, gacha rates, localization, ...).

The `.djb` ("DJBF") container exists in two header generations, distinguished by
the 16-bit (big-endian) version field:

    version  0x01xx  (major 1, "old")  -> 37-byte header, no BLAKE3
    version >=0x0200 (major 2, "new")  -> 69-byte header, +32-byte BLAKE3

Common header prefix:
    0x00  4   magic "DJBF"
    0x04  2   version (big-endian)
    0x06  2   reserved
    0x08  4   CRC-32 of plaintext  (low byte is also the IV salt)
    0x0C  4   plaintext size  (lo)
    0x10  4   plaintext size  (hi)
    0x14  1   flags  (bit0=AES-ECB, bit1=AES-CBC, bit7=FastLZ)

    --- major 2 only ---
    0x15  32  BLAKE3-256 of plaintext (anti-tamper)
    --- end major 2 only ---

    <suffix_off>      15  displaced tail of the ciphertext (block alignment)
    <suffix_off+15>    1  number of displaced tail bytes (0 if > 0xF)
      v1: suffix_off = 0x15, ciphertext starts at 0x25
      v2: suffix_off = 0x35, ciphertext starts at 0x45

Pipeline:
    ct  = body ++ tail                       # reassemble 16-byte-aligned ciphertext
    pt  = AES-256-{ECB|CBC}(ct)              # CBC IV derived from header[8]
    out = FastLZ(pt) if flags & 0x80 else pt # truncated to declared size

Keys are per (build, generation):
    kakao v1 / v2, QQ v1   (QQ v2 unknown - needs a QQ build to recover).
    The v1 (kakao/QQ) keys are from barncastle/CookieRun-DJBF-Converter;
    the v2 kakao key/IV were recovered by reverse-engineering libgame.so.

Dependencies:  pip install pycryptodome blake3   (blake3 optional, for --verify)
License: MIT.  For research / interoperability with legitimately-owned game data.
Credits: v1 KeyChain values from https://github.com/barncastle/CookieRun-DJBF-Converter
"""
from __future__ import annotations
import struct
import argparse
import sys
import os
import glob
from dataclasses import dataclass

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("Missing dependency: pip install pycryptodome")

MAGIC = b"DJBF"
FLAG_ECB, FLAG_CBC, FLAG_FASTLZ = 0x01, 0x02, 0x80

# --------------------------------------------------------------------------- #
#  Keys  (build, generation) -> (aes_key, iv_base, iv_op)
#  iv_op: 'add' -> (base[i] + salt) & 0xFF ;  'mul' -> (base[i] * salt) & 0xFF
# --------------------------------------------------------------------------- #
KEYCHAIN = {
    ("kakao", 1): (
        bytes([0xC0,0x01,0xC1,0xE1,0x26,0x11,0x10,0xDA,0x90,0x90,0x35,0x81,0xFE,0xBA,0xA9,0x7F,
               0xA1,0x45,0x1C,0x4F,0x97,0x88,0x71,0xFA,0xC3,0xF1,0xF8,0x29,0x3D,0xDE,0xE2,0xB3]),
        bytes([0x58,0xA8,0xB9,0xDD,0x13,0x61,0x62,0xAA,0x99,0x88,0x7A,0x1F,0xF2,0x3F,0x7C,0x91]),
        "add",
    ),
    ("kakao", 2): (
        bytes.fromhex("e8911c7a40bc1f6059a1d910538543bc5df44840cc684d5f1493a3f6daf0fe1e"),
        bytes.fromhex("2a790622e6fef51e5cca503eca4d5c40"),
        "mul",
    ),
    ("qq", 1): (
        bytes([0xC0,0x29,0xC1,0xE1,0x26,0x88,0x71,0xFA,0xA1,0x45,0x1C,0x4F,0x97,0xDE,0xD2,0xB3,
               0x90,0x94,0x35,0x81,0xFE,0xBA,0xA9,0x7F,0xC3,0xF1,0xF8,0x29,0x3D,0x11,0x10,0xFA]),
        bytes([0x13,0x61,0x62,0xAA,0x38,0xA8,0xB9,0xDD,0x99,0x6F,0xF2,0x3F,0x7C,0x91,0x88,0x7A]),
        "add",
    ),
    # ("qq", 2): unknown - requires a QQ (China) build to recover.
}


@dataclass(frozen=True)
class Profile:
    header_size: int
    has_blake3: bool
    suffix_off: int
    crc_init: int


PROFILE_V1 = Profile(header_size=0x25, has_blake3=False, suffix_off=0x15, crc_init=0x00000000)
PROFILE_V2 = Profile(header_size=0x45, has_blake3=True,  suffix_off=0x35, crc_init=0x20240424)


# --------------------------------------------------------------------------- #
#  CRC-32 (standard reflected polynomial; per-generation init value)
# --------------------------------------------------------------------------- #
_CRC_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if (_c & 1) else (_c >> 1)
    _CRC_TABLE.append(_c)


def crc32(data: bytes, init: int) -> int:
    c = (~init) & 0xFFFFFFFF
    for b in data:
        c = _CRC_TABLE[(b ^ c) & 0xFF] ^ (c >> 8)
        c &= 0xFFFFFFFF
    return (~c) & 0xFFFFFFFF


# --------------------------------------------------------------------------- #
#  FastLZ decompressor (levels 1 & 2)
#  Far-distance base is 8192 (== upstream MAX_L2_DISTANCE 8191, plus 1).
# --------------------------------------------------------------------------- #
_FAR_BASE = 8192


def _fastlz1(data: bytes, maxout: int) -> bytes:
    ip, bound, op = 0, len(data) - 2, bytearray()
    ctrl = data[ip] & 31; ip += 1
    while ip <= bound:
        if ctrl >= 32:
            length = (ctrl >> 5) - 1
            ref = len(op) - ((ctrl & 31) << 8) - 1
            if length == 6:
                length += data[ip]; ip += 1
            ref -= data[ip]; ip += 1
            for _ in range(length + 3):
                op.append(op[ref]); ref += 1
        else:
            cnt = ctrl + 1
            op += data[ip:ip + cnt]; ip += cnt
        if len(op) >= maxout:
            break
        if ip <= bound:
            ctrl = data[ip]; ip += 1
    return bytes(op[:maxout])


def _fastlz2(data: bytes, maxout: int) -> bytes:
    ip, n, bound, op = 0, len(data), len(data) - 2, bytearray()
    ctrl = data[ip] & 31; ip += 1
    while ip <= bound:
        if ctrl >= 32:
            length = (ctrl >> 5) - 1
            ofs = (ctrl & 31) << 8
            ref = len(op) - ofs - 1
            if length == 6:
                while True:
                    code = data[ip]; ip += 1
                    length += code
                    if code != 255:
                        break
            code = data[ip]; ip += 1
            ref -= code
            if code == 255 and ofs == (31 << 8):
                ofs = (data[ip] << 8) | data[ip + 1]; ip += 2
                ref = len(op) - ofs - _FAR_BASE
            for _ in range(length + 3):
                op.append(op[ref]); ref += 1
        else:
            cnt = ctrl + 1
            op += data[ip:ip + cnt]; ip += cnt
        if len(op) >= maxout:
            break
        if ip < n:
            ctrl = data[ip]; ip += 1
    return bytes(op[:maxout])


def fastlz_decompress(data: bytes, maxout: int) -> bytes:
    level = (data[0] >> 5) + 1
    if level == 1:
        return _fastlz1(data, maxout)
    if level == 2:
        return _fastlz2(data, maxout)
    raise ValueError(f"unsupported FastLZ level {level} (first byte 0x{data[0]:02x})")


# --------------------------------------------------------------------------- #
#  .djb parsing / decryption
# --------------------------------------------------------------------------- #
class DjbError(Exception):
    pass


@dataclass
class DjbHeader:
    version: int          # e.g. 0x0103 or 0x0200
    generation: int       # 1 or 2
    profile: Profile
    crc: int
    size: int
    flags: int
    iv_salt: int
    suffix_size: int
    blake3: bytes | None

    @property
    def uses_ecb(self): return bool(self.flags & FLAG_ECB)
    @property
    def uses_cbc(self): return bool(self.flags & FLAG_CBC)
    @property
    def uses_fastlz(self): return bool(self.flags & FLAG_FASTLZ)


def parse_header(data: bytes) -> DjbHeader:
    if data[:4] != MAGIC:
        raise DjbError("not a DJBF file (bad magic)")
    version = (data[4] << 8) | data[5]                  # big-endian
    profile = PROFILE_V2 if version >= 0x0200 else PROFILE_V1
    generation = 2 if version >= 0x0200 else 1
    crc = struct.unpack_from("<I", data, 8)[0]
    size = struct.unpack_from("<I", data, 12)[0]        # low dword (Hi is 0 in practice)
    flags = data[0x14]
    # version flag fixups (mirrors the game / reference converter)
    if version < 0x0101:
        flags &= ~FLAG_FASTLZ
    if version < 0x0102:
        flags &= ~FLAG_CBC
    ssz = data[profile.suffix_off + 15]
    if ssz > 0x0F:
        ssz = 0
    blake3 = data[0x15:0x35] if profile.has_blake3 else None
    return DjbHeader(version, generation, profile, crc, size, flags,
                     data[8], ssz, blake3)


def derive_iv(salt: int, iv_base: bytes, iv_op: str) -> bytes:
    if iv_op == "mul":
        return bytes((salt * iv_base[i]) & 0xFF for i in range(16))
    return bytes((iv_base[i] + salt) & 0xFF for i in range(16))    # 'add'


def decrypt_djb(data: bytes, build: str = "kakao") -> bytes:
    """Decrypt a .djb file (bytes) and return the plaintext."""
    h = parse_header(data)
    keyinfo = KEYCHAIN.get((build, h.generation))
    if keyinfo is None:
        raise DjbError(f"no key for build={build!r} generation={h.generation} "
                       f"(version 0x{h.version:04x})")
    key, iv_base, iv_op = keyinfo

    body = data[h.profile.header_size:]
    tail = data[h.profile.suffix_off:h.profile.suffix_off + h.suffix_size]
    ct = body + tail
    if len(ct) % 16 != 0:
        raise DjbError(f"ciphertext not 16-byte aligned ({len(ct)} bytes)")

    if h.uses_ecb:
        pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    elif h.uses_cbc:
        pt = AES.new(key, AES.MODE_CBC, derive_iv(h.iv_salt, iv_base, iv_op)).decrypt(ct)
    else:
        pt = ct

    out = fastlz_decompress(pt, h.size) if h.uses_fastlz else pt[:h.size]
    if len(out) != h.size:
        raise DjbError(f"size mismatch: got {len(out)}, expected {h.size}")
    return out


def parse_records(plaintext: bytes) -> dict:
    """Parse decrypted plaintext into an ordered {name: {key: value, ...}} dict.

    Serialization:  [u32 count]  then per record:
        [u32 field_count]  field_count*([u32 klen][key][u32 vlen][value])  [u32 nlen][name]
    The trailing per-record `name` is the row identifier (records are name-sorted).
    """
    i = 0

    def u32():
        nonlocal i
        v = struct.unpack_from("<I", plaintext, i)[0]; i += 4; return v

    def s():
        nonlocal i
        n = u32(); v = plaintext[i:i + n].decode("utf-8", "replace"); i += n; return v

    count = u32()
    out = {}
    for _ in range(count):
        nf = u32()
        fields = {}
        for _ in range(nf):
            k = s(); fields[k] = s()
        out[s()] = fields
    if i != len(plaintext):
        raise DjbError(f"trailing data after parse ({i} != {len(plaintext)}); "
                       "this file may not be a record table")
    return out


def verify(data: bytes, plaintext: bytes, build: str = "kakao") -> bool:
    """Verify decrypted plaintext: BLAKE3 (gen 2, if available) and/or CRC-32."""
    h = parse_header(data)
    if crc32(plaintext, h.profile.crc_init) != h.crc:
        return False
    if h.blake3 is not None:
        try:
            from blake3 import blake3
            return blake3(plaintext).digest() == h.blake3
        except ImportError:
            pass
    return True


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
def _write(pt, dst, as_json):
    import json
    if as_json:
        with open(dst, "w", encoding="utf-8") as f:
            json.dump(parse_records(pt), f, ensure_ascii=False, indent=2)
    else:
        with open(dst, "wb") as f:
            f.write(pt)


def _cmd_one(path, out, do_verify, build, as_json):
    data = open(path, "rb").read()
    pt = decrypt_djb(data, build)
    ok = verify(data, pt, build) if do_verify else None
    dst = out or (path + (".json" if as_json else ".bin"))
    _write(pt, dst, as_json)
    tag = "" if ok is None else (" [verified]" if ok else " [VERIFY FAILED]")
    print(f"{os.path.basename(path)} -> {dst} ({len(pt)} bytes){tag}")
    return 0 if ok is not False else 2


def _cmd_batch(folder, outdir, do_verify, build, as_json):
    os.makedirs(outdir, exist_ok=True)
    ok = fail = 0
    ext = ".json" if as_json else ".bin"
    for p in sorted(glob.glob(os.path.join(folder, "**", "*.djb"), recursive=True)):
        try:
            data = open(p, "rb").read()
            pt = decrypt_djb(data, build)
            if do_verify and not verify(data, pt, build):
                print(f"  VERIFY FAILED: {os.path.basename(p)}"); fail += 1; continue
            _write(pt, os.path.join(outdir, os.path.basename(p) + ext), as_json)
            ok += 1
        except DjbError as e:
            print(f"  ERROR {os.path.basename(p)}: {e}"); fail += 1
    print(f"\n{ok} decrypted, {fail} failed -> {outdir}")
    return 0 if fail == 0 else 2


def _cmd_info(path):
    h = parse_header(open(path, "rb").read())
    modes = [n for n, b in (("AES-ECB", h.uses_ecb), ("AES-CBC", h.uses_cbc),
                            ("FastLZ", h.uses_fastlz)) if b]
    print(f"file        : {os.path.basename(path)}")
    print(f"version     : 0x{h.version:04x} (generation {h.generation})")
    print(f"header size : 0x{h.profile.header_size:02x}")
    print(f"flags       : 0x{h.flags:02x} ({'+'.join(modes) or 'raw'})")
    print(f"plain size  : {h.size}")
    print(f"crc32       : 0x{h.crc:08x} (init 0x{h.profile.crc_init:08x})")
    print(f"blake3      : {h.blake3.hex() if h.blake3 else '(none)'}")
    print(f"suffix size : {h.suffix_size}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Cookie Run .djb decryptor")
    ap.add_argument("path", help=".djb file, or a folder with --batch")
    ap.add_argument("-o", "--output", help="output file (single-file mode)")
    ap.add_argument("--batch", metavar="OUTDIR", help="decrypt every *.djb under PATH")
    ap.add_argument("--build", choices=["kakao", "qq"], default="kakao",
                    help="game build whose keys to use (default: kakao)")
    ap.add_argument("--verify", action="store_true", help="check CRC-32 / BLAKE3 integrity")
    ap.add_argument("--json", action="store_true",
                    help="parse the decrypted records and write JSON instead of raw .bin")
    ap.add_argument("--info", action="store_true", help="print header info only")
    a = ap.parse_args(argv)
    try:
        if a.info:
            return _cmd_info(a.path)
        if a.batch:
            return _cmd_batch(a.path, a.batch, a.verify, a.build, a.json)
        return _cmd_one(a.path, a.output, a.verify, a.build, a.json)
    except DjbError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
