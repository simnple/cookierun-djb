# cookierun-djb

A decryptor and format-documentation for the **`.djb`** game-data files used by
**Cookie Run for Kakao** (`com.devsisters.CookieRunForKakao`, cocos2d-x native
engine). `.djb` files hold the game's balance tables, gacha/probability data,
localization text, and other configuration as encrypted + compressed blobs.

This repo is the result of a reverse-engineering effort and contains:

- **`cookierun_djb.py`** — a dependency-light Python decryptor + parser (library + CLI).
- **`docs/FORMAT.md`** — the full on-disk format specification (both generations).
- **`docs/REVERSING.md`** — how the format, keys, and (non-standard) FastLZ were
  recovered.

> **208 / 208** shipped `.djb` files in the analysed build decrypt and pass
> **CRC-32 + BLAKE3** verification byte-for-byte.

### Format generations

The `DJBF` container has evolved; the 16-bit big-endian *version* field selects
the layout:

| version | gen | header | integrity | AES key | CBC IV |
|--------:|:---:|:------:|-----------|---------|--------|
| `0x01xx` | 1 (old) | 37 B (`0x25`) | CRC-32 | kakao/QQ v1 | `base[i] + salt` |
| `≥0x0200` | 2 (new) | 69 B (`0x45`) | CRC-32 **+ BLAKE3-256** | kakao v2 | `base[i] * salt` |

The current Kakao build ships 202 gen-2 files and 6 leftover gen-1 files; the
tool auto-detects and handles both.

---

## ⚖️ Disclaimer

For **research, education, and interoperability** with game data you already own.
**Not affiliated with or endorsed by Devsisters.** Contains **no** game assets —
only code and a description of a file format. The cryptographic constants are
facts recovered from the freely-distributed application binary. Do not use this
to redistribute game content or to gain an unfair advantage in online play.

---

## Install

```bash
pip install -r requirements.txt        # pycryptodome (required), blake3 (optional)
```

## Usage

```bash
python cookierun_djb.py CookieBalance.djb --info           # inspect header
python cookierun_djb.py CookieBalance.djb --verify          # -> CookieBalance.djb.bin (raw)
python cookierun_djb.py CookieBalance.djb --json            # -> CookieBalance.djb.json (readable!)
python cookierun_djb.py path/to/assets --batch out/ --json --verify
python cookierun_djb.py file.djb --build qq                 # use QQ (China) keys
```

### Opening the result

A raw `.bin` is the game's serialized record table, not plain text — use
**`--json`** to parse it into readable `{name: {key: value}}` JSON:

```jsonc
// CookieBalance.djb.json
{
  "AlchemistBalanceOff":      { "resource_key": "ch34", "value": "0" },
  "Baduk_CoinCount":          { "resource_key": "ch78,ch79", "value": "8" }
}
// l10n-ko.djb.json
{ "$ActivePoint.activity_desc.1": { "ko": "출석선물로 %d 포인트를 얻었습니다." } }
```

Or from Python: `parse_records(decrypt_djb(open(path,'rb').read()))`.

```
$ python cookierun_djb.py MagicStatList.djb --info
file        : MagicStatList.djb
version     : 0x0103 (generation 1)
header size : 0x25
flags       : 0x82 (AES-CBC+FastLZ)
plain size  : 13542
crc32       : 0x19f925a7 (init 0x00000000)
blake3      : (none)
suffix size : 7
```

Library use:

```python
from cookierun_djb import decrypt_djb, verify
data = open("CookieBalance.djb", "rb").read()
pt = decrypt_djb(data)            # build="kakao" by default
assert verify(data, pt)
```

The plaintext is a length-prefixed key/value token stream (`[u32 len][bytes]` …)
describing tables such as `resource_key` → `value`.

---

## Format (TL;DR)

```
        common header                         gen-2 only
  ┌───────────────────────────┐        ┌────────────────────┐
  0x00 "DJBF" | 0x04 version(BE) | 0x08 crc32 | 0x0C size(u64) | 0x14 flags |
  [ 0x15 BLAKE3-256 (32B, gen-2 only) ]  suffix[15]  suffix_size(1)  ciphertext…

  flags:  0x01 AES-ECB   0x02 AES-CBC   0x80 FastLZ

  ct  = body ++ displaced_tail           # reassemble 16-byte-aligned ciphertext
  pt  = AES-256-CBC(ct, IV)              # IV from header[8] (+ or * base vector)
  out = FastLZ(pt)                        # if flags & 0x80, else pt[:size]
```

Two quirks (both reproduced):

1. **CBC IV is derived per file** from one header byte and a fixed 16-byte base
   — `add` for gen-1, `multiply` for gen-2.
2. **FastLZ level-2 far-match base is 8192** (`MAX_L2_DISTANCE 8191 + 1`); getting
   this wrong corrupts the level-2 files.

Full spec, keys and IV vectors: **[docs/FORMAT.md](docs/FORMAT.md)**.

---

## How it was reversed (short version)

`.djb` bodies look like noise, and `libgame.so` (which holds the loader) is
**packed**: ~100 % of its `.text` is XOR-obfuscated on disk with a repeating
32-byte key (applied at runtime by the `libfilequeue.so` RASP). The XOR key was
recovered with a known-plaintext attack (using the unpacked sibling
`libfilequeue.so` as a reference distribution of real AArch64 code); the code was
decrypted and the loader read out in a decompiler to extract the gen-2 algorithm,
AES key, IV derivation and the FastLZ variant. The gen-1 keys come from
[barncastle/CookieRun-DJBF-Converter](https://github.com/barncastle/CookieRun-DJBF-Converter).
Full write-up: **[docs/REVERSING.md](docs/REVERSING.md)**.

---

## Limitations / notes

- **QQ (China) gen-2 key** is unknown (the analysed binary was the Kakao build).
  `--build qq` works for gen-1 files only.
- Decryption keys ship in the client, so this is **obfuscation, not a trust
  boundary** — which is exactly why it can be undone. Server-authoritative
  validation is the only real protection for game-economy data.

## Credits

- Gen-1 `KeyChain` (kakao/QQ v1 keys + IV vectors) and the C# converter:
  [barncastle/CookieRun-DJBF-Converter](https://github.com/barncastle/CookieRun-DJBF-Converter).
- Gen-2 (new) format, AES key, and IV derivation: this project.

## License

MIT — see [LICENSE](LICENSE).
