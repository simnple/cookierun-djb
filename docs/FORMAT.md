# `.djb` file format

`.djb` ("DJBF") is the container Cookie Run uses for native game-data assets
(balance tables, gacha rates, localization, …). It is parsed by
`CRXDJBFileLoader` / the DSXFramework data loader inside `libgame.so`.

All multi-byte integers are **little-endian** *except* the `version` field, which
is **big-endian**. There are two header generations selected by `version`.

## Common header prefix (offsets 0x00–0x14)

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| `0x00` | 4 | magic | ASCII `"DJBF"` = `44 4A 42 46` |
| `0x04` | 2 | version (BE u16) | e.g. `01 03` → `0x0103`; `02 00` → `0x0200` |
| `0x06` | 2 | reserved | |
| `0x08` | 4 | CRC-32 of plaintext | low byte (`[0x08]`) is the IV salt |
| `0x0C` | 4 | plaintext size (lo) | |
| `0x10` | 4 | plaintext size (hi) | 0 in practice |
| `0x14` | 1 | **flags** | `0x01`=AES-ECB, `0x02`=AES-CBC, `0x80`=FastLZ |

Version-gated flag fixups (the engine clears unsupported flags):
`version < 0x0101` → no FastLZ; `version < 0x0102` → no CBC.

## Generation-specific tail

### Generation 1 — `version 0x01xx` (header = 37 bytes, `0x25`)

| Offset | Size | Field |
|-------:|-----:|-------|
| `0x15` | 15 | displaced tail of ciphertext |
| `0x24` | 1 | tail byte count (`0` if `> 0x0F`) |
| `0x25` | … | ciphertext body |

No BLAKE3. Integrity = **CRC-32 with init `0`** (standard).

### Generation 2 — `version >= 0x0200` (header = 69 bytes, `0x45`)

| Offset | Size | Field |
|-------:|-----:|-------|
| `0x15` | 32 | **BLAKE3-256** of plaintext (anti-tamper) |
| `0x35` | 15 | displaced tail of ciphertext |
| `0x44` | 1 | tail byte count (`0` if `> 0x0F`) |
| `0x45` | … | ciphertext body |

Integrity = **CRC-32 with init `0x20240424`** *and* BLAKE3-256. A tamper trips the
engine's *"DSX Binary Data Cracked"* abort path. Gen-2 is gen-1 with a 32-byte
BLAKE3 inserted right after the flags byte (everything below `0x15` shifts +0x20).

## Decode pipeline

```
tail = file[suffix_off : suffix_off + tail_count]   # suffix_off = 0x15 (gen1) / 0x35 (gen2)
ct   = file[header_size:] ++ tail                   # header_size = 0x25 / 0x45

if   flags & 0x01:  pt = AES256_ECB_decrypt(KEY, ct)
elif flags & 0x02:  pt = AES256_CBC_decrypt(KEY, IV, ct)
else:               pt = ct

out  = FastLZ_decompress(pt, size)  if flags & 0x80  else  pt[:size]
```

The displaced tail trick stores the final `tail_count` bytes of the ciphertext in
the header so the on-disk body length is a multiple of 16
(`tail_count = (16 - body_len % 16) % 16`).

## Keys & IV

`salt = file[0x08]` (low byte of the CRC field).
`IV[i] = op(base[i], salt) & 0xFF`, where `op = +` (gen-1) or `*` (gen-2).
ECB uses no IV.

### kakao (Korea build)

```
gen-1 key:
  C0 01 C1 E1 26 11 10 DA 90 90 35 81 FE BA A9 7F
  A1 45 1C 4F 97 88 71 FA C3 F1 F8 29 3D DE E2 B3
gen-1 IV base:   58 A8 B9 DD 13 61 62 AA 99 88 7A 1F F2 3F 7C 91     (op = add)

gen-2 key:
  E8 91 1C 7A 40 BC 1F 60 59 A1 D9 10 53 85 43 BC
  5D F4 48 40 CC 68 4D 5F 14 93 A3 F6 DA F0 FE 1E
gen-2 IV base:   2A 79 06 22 E6 FE F5 1E 5C CA 50 3E CA 4D 5C 40     (op = mul)
```

### QQ (China build)

```
gen-1 key:
  C0 29 C1 E1 26 88 71 FA A1 45 1C 4F 97 DE D2 B3
  90 94 35 81 FE BA A9 7F C3 F1 F8 29 3D 11 10 FA
gen-1 IV base:   13 61 62 AA 38 A8 B9 DD 99 6F F2 3F 7C 91 88 7A     (op = add)

gen-2 key:       (unknown — requires a QQ build to recover)
```

## FastLZ

Auto-selected from `pt[0] >> 5` (level 1 or 2). It matches reference FastLZ; the
only subtlety is the level-2 long-distance match:

```
ref = op - ofs - 8192       # = MAX_L2_DISTANCE(8191) + 1
```

## Plaintext layout (record table)

The decompressed plaintext is a serialized, name-sorted table of records. Every
string is `[u32 length][utf-8 bytes]`.

```
[u32 record_count]
record × record_count:
    [u32 field_count]
    field × field_count:
        [str key]
        [str value]
    [str name]                  # the record's identifier (sorted), comes last
```

So a record maps to `name -> { key: value, ... }`. Examples:

```
CookieBalance.djb : "AlchemistBalanceOff" -> {resource_key:"ch34", value:"0"}
MagicStatList.djb : "1001"                -> {DisplayMagnitude:""}
l10n-ko.djb       : "$ActivePoint.activity_desc.1" -> {ko:"출석선물로 %d 포인트를 얻었습니다."}
```

`cookierun_djb.py --json` parses this into `{name: {key: value}}` JSON.

## Credits

Gen-1 keys/IV from
[barncastle/CookieRun-DJBF-Converter](https://github.com/barncastle/CookieRun-DJBF-Converter).
Gen-2 format/keys reverse-engineered from `libgame.so` (see REVERSING.md).
