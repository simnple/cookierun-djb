# How the `.djb` format was reverse-engineered

A narrative of how the format, the AES key, the per-file IV, and the (non-standard)
FastLZ variant were recovered. Tools used: a custom Python ELF/AArch64 toolkit,
`capstone`, `jadx`, and Ghidra (headless).

## 1. First wall: the payload is not "just compressed"

`.djb` bodies have ~8.0 bits/byte entropy and do not inflate as zlib/deflate at
any offset. Header bytes were stable across files (notably a constant byte at
offset `0x14` and zeros at `0x10..0x14`), which hinted at a structured header
rather than pure ciphertext — but the body was clearly transformed.

## 2. Bigger wall: `libgame.so` is packed

The loader lives in the native engine `libgame.so`. Static analysis failed
because the library is **packed**:

- `.text` entropy ≈ **7.71** (normal AArch64 code is ~6.0).
- Every sampled function symbol (`JNI_OnLoad`, `yyjson_*`, `CryptoPP::*`) decoded
  to garbage / illegal instructions.
- `DT_INIT` / `DT_INIT_ARRAY` are empty — the library does not unpack *itself*.
- `.rodata`, `.plt`, symbol tables are plaintext (entropy 5–6), which is why
  strings and the symbol table were readable while code was not.

Comparing with the sibling library `libfilequeue.so` showed the latter is
plaintext AArch64 (entropy 6.69) and contains loader-hook primitives
(`android_dlopen_ext`, `dlopen`, `mprotect`, `/proc/self/maps`) — i.e.
**`libfilequeue.so` is the packer** (a DoveRunner/AppSealing-style RASP) that
decrypts `libgame.so` in memory at load time.

## 3. Cracking the packer: 32-byte repeating XOR

The packing turned out to be a **repeating 32-byte XOR** over `.text`:

- The ciphertext byte histogram is *not* uniform (so it is not AES/stream) and
  the index-of-coincidence rises and plateaus at a period of **32 bytes** — the
  signature of a fixed-key repeating XOR.
- The key was recovered with a **known-plaintext / reference-distribution attack**:
  for each of the 32 key columns, pick the byte that makes the decrypted column's
  value distribution best match real AArch64 code — using the *plaintext*
  `libfilequeue.so` (same compiler/target) as the reference model.

XOR-decrypting `.text` with the recovered 32-byte key produced **100 % valid
AArch64** — every function symbol now disassembles with a correct prologue
(`stp x29, x30, [sp, …]` etc.), and `JNI_OnLoad` even builds the constant
`0x00010004` (`JNI_VERSION_1_4`). The reconstructed library is a normal ELF you
can throw at a decompiler.

## 4. Reading the loader

With a decompilable binary, the `.djb` path was followed:

- The generic loader funnel `FUN_014243ec` parses the 69-byte header, reassembles
  the block-aligned ciphertext (`body ++ displaced_tail`), and calls the
  decryptor then `fastlz_decompress`.
- The decryptor (`FUN_014248e0` → CryptoPP `BlockOrientedCipherModeBase`, or
  `FUN_01424714` → `ECB_OneWay::ProcessData`) calls `SetKey` with a **32-byte key
  at `DAT_00c8ab24`** → AES-256.
- The CBC IV is built in `FUN_014248e0` as `header[8] * DAT_00ba9a50[i]`
  (byte-wise, mod 256).
- Integrity: a CRC-32 (table at `DAT_00de6b3c`, init `0x20240424`) **and** a
  BLAKE3-256 (`blake3_hasher_*`) over the plaintext; a mismatch logs
  *"DSX Binary Data Cracked"*.

## 5. The FastLZ off-by-one

A first implementation decrypted+decompressed correctly for ~159/208 files; the
rest had the right size but the wrong bytes — all **FastLZ level 2**. Decompiling
`fastlz2_decompress` showed the long-distance match uses:

```c
__src = __dest + (-0x2000 - big_endian_16(...));   // 0x2000 = 8192
```

i.e. a far-match base of **8192**, where upstream FastLZ uses **8191**. Using the
binary's value pushed verification to **202/208**, each confirmed by matching the
file's stored **BLAKE3** hash exactly (cryptographic proof of byte-exact output).

## 6. The two generations

Reversing the 2026 Kakao build cleanly explained 202/208 files but left 6
stubborn ones whose version field reads `01 03` (`0x0103`) instead of `02 00`
(`0x0200`). They have no BLAKE3, the header is shorter, and the gen-2 key/IV
produce garbage — they are simply an **older generation** of the same format,
left over in the package.

The missing pieces (old header layout, old key, and the `add`-based IV) matched
the prior work in
[barncastle/CookieRun-DJBF-Converter](https://github.com/barncastle/CookieRun-DJBF-Converter),
a C# converter for older Cookie Run builds. Cross-referencing it:

| | generation 1 (old) | generation 2 (new) |
|---|---|---|
| version | `0x01xx` | `≥ 0x0200` |
| header | 37 B, no BLAKE3 | 69 B, +32 B BLAKE3 |
| AES key (kakao) | `C0 01 C1 E1 …` | `E8 91 1C 7A …` |
| CBC IV | `base[i] + salt` | `base[i] * salt` |
| CRC-32 init | `0` | `0x20240424` |

So gen-2 = gen-1 + an inserted BLAKE3 hash, a rotated key, a multiplicative IV,
and a salted CRC init. The reference repo's gen-1 `KeyChain` plus this project's
gen-2 reversing together decrypt and verify **all 208** files. (The two efforts
also independently agree on the FastLZ far-match base of 8192 — barncastle writes
it as `MAX_L2_DISTANCE(8191) + 1`, the binary as `-0x2000`.)

## Takeaway

Every layer here — the native packer XOR and the `.djb` AES — ships its keys
inside the client. Client-side encryption raises the bar for casual data-mining
but is **obfuscation, not a trust boundary**: a determined reverser recovers the
keys, as demonstrated. Anything that matters for fairness (currency, drop rates,
progression) must be validated server-side.
