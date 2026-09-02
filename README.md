# DES in C

A from-scratch implementation of the **DES (Data Encryption Standard)** block cipher in C11, with no external dependencies.

> ⚠️ **DES is broken.** Its effective 56-bit key falls to brute force on modern hardware; NIST formally withdrew it in 2005. This is an educational implementation. Don't use it to protect real data — use AES-GCM or ChaCha20-Poly1305 through an audited library (libsodium, OpenSSL) instead.

## What this is

DES encrypts and decrypts 64-bit blocks (a fixed-size chunk of 8 bytes) using a 64-bit key (56 bits of actual entropy — the other 8 are parity bits the algorithm ignores). This implementation covers the full block cipher as defined in FIPS PUB 46-3, the official government spec that defines exactly how DES must behave:

- Initial and final permutation (`IP` / `IP⁻¹`) — a fixed reshuffling of the 64 bits, always the same regardless of the key.
- Key schedule: `PC-1` → 16 rotations → `PC-2`, producing 16 round subkeys — one derived mini-key per round, generated from the main key.
- The Feistel round function: expansion (`E`), XOR with the subkey, substitution through 8 S-boxes, and permutation (`P`). S-boxes are fixed lookup tables that swap bits in a way that can't be undone with simple math — they're what makes DES's math non-linear and hard to reverse without the key.
- 16 Feistel rounds, with decryption running the same code path in reverse subkey order — this "Feistel" structure is the whole reason encryption and decryption can share nearly identical code (see the comments at the top of `src/des.c` for the full reasoning).

## Why it's built this way

A few choices in this codebase exist specifically to avoid classes of bugs that are common in hand-rolled crypto code:

- **Fixed-width types everywhere** (`uint64_t`, `uint32_t`, `uint8_t` from `<stdint.h>`, never `int` or `long`). DES is defined bit-by-bit, and a plain `int`'s size can vary between machines. Shifting bits past the actual width of a variable is "undefined behavior" in C — the compiler is allowed to produce anything, including silently wrong output with no warning. Fixed-width types pin down the size everywhere, so every bit operation behaves the same on any machine.
- **One `permute()` helper instead of six different functions.** `IP`, `IP⁻¹`, `E`, `P`, `PC-1`, and `PC-2` all do the same operation — pick bits from an input table and reassemble them — with different table sizes. Writing this once and driving it with data avoids six copies of the same indexing bug.
- **Every module only knows what it needs.** `des_tables` holds pure data, nothing else. `des_feistel` doesn't know how subkeys are derived — it just takes one as a `uint64_t`. `des.c` (the block cipher core) never includes `des_modes.h` (the future higher-level layer). This isn't just style: it keeps a bug in one layer (say, a padding scheme added later) from silently breaking the layer underneath it (the cipher itself).
- **Round keys are wiped after use.** `des.c` zeroes out the subkey buffer through a `volatile` pointer (a marker that tells the compiler "don't optimize away reads/writes to this") before returning, instead of a plain `memset`. Compilers are allowed to delete a `memset` if they can prove the memory is never read again afterward — a real, documented class of bug where key material silently keeps sitting in memory instead of being erased.
- **Tables are transcribed exactly as FIPS 46-3 prints them** (numbered starting at 1, most-significant-bit first — the spec's own numbering, not typical C-array indexing), not pre-converted to C-style offsets. A transcription error in one of these tables doesn't crash anything — it silently produces a cipher that "works" but isn't real DES and won't match anyone else's implementation. Keeping the tables visually comparable to the spec makes that kind of error easy to catch by eye.

## Structure

```
include/
  des_tables.h         table declarations (IP, IP⁻¹, E, P, PC-1, PC-2, SHIFTS, SBOX)
  des_keyschedule.h    key schedule declaration
  des_feistel.h        Feistel round function declaration
  des.h                public API: des_encrypt_block / des_decrypt_block
  des_modes.h          reserved for block cipher modes (empty for now)
src/
  des_tables.c         table definitions, no logic
  des_keyschedule.c    PC-1 -> rotations -> PC-2
  des_feistel.c        E -> XOR -> S-boxes -> P
  des.c                IP -> 16 Feistel rounds -> IP⁻¹ (the actual cipher)
  des_modes.c          placeholder, excluded from the build
examples/
  main.c               encrypts and decrypts a sample text
Makefile
```

## Building and running

Requires a C11 compiler (GCC or Clang) and `make`. No dependencies.

```bash
make examples          # builds the core + the demo program
./build/bin/des_demo   # runs it with a default sample text
```

Pass your own text as an argument:

```bash
./build/bin/des_demo "this is my message"
```

That prints each 8-byte block in hex before and after encryption, then decrypts everything back and confirms it matches the original text.

Note: the demo encrypts each block independently in a loop. That pattern has a name — ECB (Electronic Codebook) — and it's a known-weak way to encrypt anything longer than one block, because identical plaintext blocks always produce identical ciphertext blocks, leaking patterns. Fine here for seeing the cipher work; not something to use for real multi-block encryption.

## Using the API

The public surface is two functions operating on a single 64-bit block at a time:

```c
#include "des.h"

uint64_t des_encrypt_block(uint64_t block, uint64_t key);
uint64_t des_decrypt_block(uint64_t block, uint64_t key);
```

```c
#include <inttypes.h>
#include <stdio.h>
#include "des.h"

int main(void)
{
    const uint64_t key   = UINT64_C(0x133457799BBCDFF1);
    const uint64_t plain = UINT64_C(0x0123456789ABCDEF);

    const uint64_t cipher    = des_encrypt_block(plain, key);
    const uint64_t recovered = des_decrypt_block(cipher, key);

    printf("cipher:    %016" PRIX64 "\n", cipher);     /* 85E813540F0AB405 */
    printf("recovered: %016" PRIX64 "\n", recovered);  /* 0123456789ABCDEF */

    return 0;
}
```

Compile it directly against the core sources:

```bash
cc -std=c11 -Iinclude my_program.c src/des_tables.c src/des_keyschedule.c \
   src/des_feistel.c src/des.c -o my_program
```

Both functions are "pure" (same input always gives the same output, no hidden state) and "reentrant" (no shared/global variables), so they're safe to call from multiple threads at once without any locking.

## Known limitations

- **Not constant-time.** How long the S-box lookups take can vary very slightly depending on the actual bit values involved. In theory, someone who can precisely measure how long encryption takes (a "timing side channel") could use that to guess bits of the key. This implementation makes no attempt to prevent that.
- No detection of "weak" or "semi-weak" keys — a handful of specific DES keys are known to behave in unusually predictable ways.
- No Triple DES (running DES three times with different keys, the historical fix for DES's short key length).
- Operates on single 64-bit blocks only — there's no higher-level function yet that takes an arbitrary-length message (a string, a file) and handles splitting it into blocks and padding the last one correctly.

These are acceptable for a project whose goal is to show how DES works internally, and they're listed here instead of left for someone to discover the hard way.

## References

- [FIPS PUB 46-3 — Data Encryption Standard](https://csrc.nist.gov/pubs/fips/46-3/final)
- [NIST SP 800-38A — Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final)

---

Made by **dtpollo**.
