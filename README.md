# DES in C

A from-scratch implementation of the **DES (Data Encryption Standard)** block cipher in C11, together with the **modes of operation** that make it usable on real messages (PKCS#7 padding, ECB and CBC) and a **parallel brute-force key search** that measures what its 56-bit key actually costs an attacker. No external dependencies.

> ⚠️ **DES is broken.** Its effective 56-bit key falls to brute force on modern hardware, and NIST formally withdrew it in 2005. This is an educational implementation. Do not use it to protect real data. Use AES-GCM or ChaCha20-Poly1305 through an audited library such as libsodium or OpenSSL instead.

## What is implemented

| Layer | Header | What it gives you |
|---|---|---|
| Block cipher | `des.h` | The raw 64-bit primitive, one block per call |
| Byte API | `des_api.h` | The same thing on byte buffers, with length validation |
| **Modes of operation** | `des_modes.h` | **PKCS#7 padding, ECB and CBC, for messages of any length** |
| Experiments | `benchmark_bruteForce/` | Known-plaintext key search, sequential and threaded |

Most callers want `des_modes.h`, because that is the layer that accepts a message of any length. The two lower layers are documented further down for completeness.

## Quick start

Requires a C11 compiler (GCC or Clang) and `make`. The cipher has no dependencies, while the brute-force experiments additionally use POSIX threads (`-pthread`), which ship with glibc and Clang on Linux and macOS.

```bash
make test          # runs both test suites: 66 checks for the cipher and modes, 18 for the attack
make experiments   # shows ECB vs CBC, the effect of the IV, and error propagation
make benchmark     # measures key-search throughput, speedup and efficiency
make examples      # builds and runs the raw block-primitive demo
make help          # lists every target
```

---

# Using the modes of operation

Everything in this section comes from `des_modes.h`. Include it and you get padding, ECB and CBC.

```c
#include "des_modes.h"
```

## The rules that apply to every call

These are the same for all four mode functions, so they are stated once here.

**Sizes.** All three are exactly 8 bytes, and the library rejects anything else rather than truncating it.

| Constant | Value | Meaning |
|---|---|---|
| `DES_KEY_BYTES` | 8 | Key length |
| `DES_BLOCK_BYTES` | 8 | Block length |
| `DES_IV_BYTES` | 8 | Initialization vector length, CBC only |

**You own the memory.** Nothing here allocates. You pass the output buffer and its capacity, and you get back the number of bytes actually written through `*out_len`.

| Direction | Buffer size you must provide |
|---|---|
| Encrypting | `des_padded_len(plaintext_len)` bytes |
| Decrypting | `ciphertext_len` bytes |

`des_padded_len()` always rounds **up past** the block size, because there is always at least one padding byte. A 16-byte message therefore needs 24 bytes of room, not 16.

**Status codes.** Every function returns `des_status_t`, and `*out_len` is written only when the result is `DES_OK`. On any error the contents of the output buffer are unspecified.

| Code | Meaning |
|---|---|
| `DES_OK` | Success |
| `DES_ERR_INVALID_LENGTH` | Key, IV or ciphertext length is wrong |
| `DES_ERR_INVALID_PADDING` | The decrypted padding is malformed, which usually means a wrong key |
| `DES_ERR_BUFFER_TOO_SMALL` | Your output buffer is not large enough |

Always check the return value. A wrong key normally surfaces as `DES_ERR_INVALID_PADDING`, so the check is what tells you decryption failed.

## ECB (Electronic Codebook)

ECB encrypts every block on its own, so that `Cᵢ = E_K(Pᵢ)`. It needs no IV.

```c
des_status_t des_ecb_encrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *out, size_t out_cap, size_t *out_len);

des_status_t des_ecb_decrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             uint8_t *out, size_t out_cap, size_t *out_len);
```

```c
const uint8_t key[DES_KEY_BYTES] = { 0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1 };
const char *message = "Hola, DES desde C!";

uint8_t cipher[64];
size_t cipher_len = 0;

if (des_ecb_encrypt(key, DES_KEY_BYTES,
                    (const uint8_t *)message, strlen(message),
                    cipher, sizeof cipher, &cipher_len) != DES_OK) {
    return 1;
}
/* cipher_len == 24
   702FCBA6F3D94507A6C82CE5951EA52554C2C608F7B31462 */
```

> ⚠️ **ECB leaks the structure of your message.** Because the transformation is deterministic and each block is independent, two equal plaintext blocks always produce the same ciphertext block. Encrypting `ABCDEFGHABCDEFGHABCDEFGHABCDEFGH` with this library returns the block `0EE11BD2808EF0A1` four times in a row, so an observer who never recovers the key still learns that the message contains four identical blocks and where they are. Use ECB only to study that effect. For anything else use CBC.

## CBC (Cipher Block Chaining)

CBC chains each block into the next, so that `C₀ = IV` and `Cᵢ = E_K(Pᵢ ⊕ Cᵢ₋₁)`, which removes the repetition that ECB exposes. Decryption computes `Pᵢ = D_K(Cᵢ) ⊕ Cᵢ₋₁`.

```c
des_status_t des_cbc_encrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *iv, size_t iv_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *out, size_t out_cap, size_t *out_len);

des_status_t des_cbc_decrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *iv, size_t iv_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             uint8_t *out, size_t out_cap, size_t *out_len);
```

```c
const uint8_t key[DES_KEY_BYTES] = { 0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1 };
const uint8_t iv[DES_IV_BYTES]   = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88 };
const char *message = "Hola, DES desde C!";

uint8_t cipher[64];
size_t cipher_len = 0;

if (des_cbc_encrypt(key, DES_KEY_BYTES, iv, DES_IV_BYTES,
                    (const uint8_t *)message, strlen(message),
                    cipher, sizeof cipher, &cipher_len) != DES_OK) {
    return 1;
}
/* cipher_len == 24
   76CA4BD63050221141A90BC6D00A58DB44DC3889B2C7692B */
```

Decryption needs the same key and the same IV. It also validates and strips the padding, so `*out_len` is the true plaintext length and the bytes past it are leftover padding.

```c
uint8_t plain[64];
size_t plain_len = 0;

switch (des_cbc_decrypt(key, DES_KEY_BYTES, iv, DES_IV_BYTES,
                        cipher, cipher_len, plain, sizeof plain, &plain_len)) {
case DES_OK:                   break;  /* plain[0 .. plain_len-1] is the message */
case DES_ERR_INVALID_PADDING:  return 1;  /* wrong key, wrong IV, or altered data */
default:                       return 1;
}
```

In `des_cbc_decrypt` the output buffer may safely overlap the input buffer, because each ciphertext block is saved before the plaintext is written over it.

## The initialization vector

The IV is the value that takes the place of `C₀`, so it is what makes the first block depend on something that changes between messages. Four rules cover its correct use.

1. **It is exactly 8 bytes.** Any other length returns `DES_ERR_INVALID_LENGTH`.
2. **It does not need to be secret.** The receiver needs it in order to decrypt, so the normal practice is to send it in the clear, usually prepended to the ciphertext.
3. **It must be unpredictable and fresh for every message.** Reusing an IV with the same key reintroduces exactly the determinism that CBC exists to remove, because the same plaintext then produces the same ciphertext again.
4. **This library does not generate it.** You supply it, so generate it from the operating system rather than from a counter or from `rand()`.

```c
#include <sys/random.h>

uint8_t iv[DES_IV_BYTES];

if (getrandom(iv, sizeof iv, 0) != (ssize_t)sizeof iv) {
    return 1;
}
```

A convenient layout is to write the IV first and the ciphertext after it, so that one buffer carries everything the receiver needs:

```c
uint8_t packet[DES_IV_BYTES + 64];
size_t cipher_len = 0;

memcpy(packet, iv, DES_IV_BYTES);

if (des_cbc_encrypt(key, DES_KEY_BYTES, iv, DES_IV_BYTES,
                    (const uint8_t *)message, strlen(message),
                    &packet[DES_IV_BYTES], sizeof packet - DES_IV_BYTES,
                    &cipher_len) != DES_OK) {
    return 1;
}
/* send packet[0 .. DES_IV_BYTES + cipher_len - 1] */
```

Changing only the IV changes the whole ciphertext. Encrypting one message under two different IVs with the same key alters all five ciphertext blocks and 149 of the 320 ciphertext bits, which is 46.6 percent and therefore close to the 50 percent expected from an unpredictable transformation.

## PKCS#7 padding

ECB and CBC apply padding automatically, so you only need these two functions if you want to pad separately.

```c
size_t des_padded_len(size_t data_len);

des_status_t des_pkcs7_pad(const uint8_t *data, size_t data_len,
                           uint8_t *out, size_t out_cap, size_t *out_len);

des_status_t des_pkcs7_unpad(const uint8_t *data, size_t data_len, size_t *out_len);
```

Padding appends `p` copies of the byte whose value is `p`, where `p` is the number of bytes needed to fill the final block. The count never reaches zero, so a message that is already a multiple of 8 gains one complete extra block, and that is precisely what makes the padding unambiguous to remove, because the last byte always states how many bytes to discard.

| Message length | Padded length | Bytes appended |
|---:|---:|---|
| 5 | 8 | `03 03 03` |
| 7 | 8 | `01` |
| 8 | 16 | `08` eight times |
| 18 | 24 | `06` six times |

`des_pkcs7_unpad` validates the trailer instead of trusting it, rejecting a zero count, a count above the block size, and any run whose bytes do not all equal the count. It reports the unpadded length through `*out_len` and leaves the data itself untouched.

## Compiling your own program

```bash
cc -std=c11 -Iinclude my_program.c src/des_tables.c src/des_keyschedule.c \
   src/des_feistel.c src/des.c src/des_api.c src/des_modes.c -o my_program
```

All of these functions are pure, in the sense that the same input always produces the same output with no hidden state, and reentrant, because no global variables are involved. They are therefore safe to call from several threads at once without locking.

---

# The lower layers

You normally do not need these, since the modes layer covers messages of any length. They are here because the modes are built on them.

## The raw block primitive

`des.h` trusts its caller completely and always transforms exactly one 64-bit block, with no padding, no IV and no chaining.

```c
#include "des.h"

uint64_t des_encrypt_block(uint64_t block, uint64_t key);
uint64_t des_decrypt_block(uint64_t block, uint64_t key);
```

Bit 1 of the FIPS specification is the most significant bit of these values, so eight bytes of text are packed most significant byte first. Encrypting `0x0123456789ABCDEF` under key `0x133457799BBCDFF1` yields `0x85E813540F0AB405`, which is the known answer vector printed in the standard.

## The single-block byte API

`des_api.h` is the same primitive on byte buffers, with explicit length validation. It handles exactly one block per call, so a length other than 8 returns `DES_ERR_INVALID_LENGTH` instead of reading out of bounds.

```c
#include "des_api.h"

des_status_t des_encrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t out[DES_BLOCK_BYTES]);

des_status_t des_decrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         uint8_t out[DES_BLOCK_BYTES]);

des_status_t des_key_schedule(const uint8_t *key, size_t key_len,
                              uint64_t round_keys[static DES_ROUNDS]);

des_status_t des_check_parity(const uint8_t *key, size_t key_len, bool *is_valid);
```

Each byte of a DES key carries 7 data bits and 1 parity bit, which the algorithm itself ignores because PC-1 discards it. The convention is odd parity, meaning every byte should contain an odd number of 1 bits. `des_check_parity` reports whether a key follows that convention, which is a legacy hardware check rather than something that affects security.

---

# Programs

| Command | What it demonstrates |
|---|---|
| `./build/bin/des_demo ["text"]` | The raw block primitive, one block at a time |
| `./build/bin/modes_experiments` | ECB against CBC, the effect of the IV, and error propagation |
| `./build/bin/benchmark_bruteforce` | Key-search throughput, speedup, efficiency and extrapolation |
| `./build/bin/test_des` | Cipher, padding and mode tests, 66 checks |
| `./build/bin/test_bruteforce` | Key space and key-recovery tests, 18 checks |

## What the mode experiments show

`make experiments` runs three experiments, printing the output and also saving a copy under `results/`, which it creates if needed.

**Identical plaintext blocks.** Four identical plaintext blocks produce one repeated ciphertext block under ECB, while CBC produces five distinct blocks from the same input.

**The IV.** The same key and plaintext under two different IVs give completely different ciphertexts, with all five blocks and 46.6 percent of the bits changed.

**Error propagation.** One inverted ciphertext bit inside block 2 does the following:

| Plaintext block | ECB bits changed | CBC bits changed |
|---:|---:|---:|
| 1 | 0 | 0 |
| 2 | 28 | 38 |
| 3 | 0 | **1** |
| 4 | 0 | 0 |

Under ECB the damage stays inside the block that was modified, because the blocks are independent. Under CBC the damaged block is destroyed and the **next** block changes in exactly the bit that was inverted, which follows from `Pᵢ = D_K(Cᵢ) ⊕ Cᵢ₋₁`, after which the error stops. Neither mode detects the modification at all, which is why confidentiality without authentication is not enough.

Both modes match `openssl enc -des-ecb` and `-des-cbc` byte for byte on the same key, IV and input, so the padding, the block ordering and the chaining follow the standard rather than merely being self-consistent.

## The written report

[`Report_LAB02.pdf`](Report_LAB02.pdf) contains the full write-up: the implementation of the modes, the three mode experiments with their block-level tables, the brute-force method and its parallel design, the measured results with both plots, the extrapolation to the complete key space, and the security discussion.

## Brute-force experiments

`benchmark_bruteForce/` measures what the 56-bit effective key costs an attacker. The experiments deliberately reuse the same `des_encrypt_block` as the rest of the library, so there is no separate fast path.

**The controlled key space.** Searching all 2⁵⁶ effective keys is not something to run, so a search varies only the low `n` bits of the 56 effective key bits and fixes the rest to a known prefix. Every candidate goes through one mapping:

```
candidate (n bits) -> 56 effective bits -> 64-bit DES key
```

The 56 effective bits are laid out 7 per key byte, most significant group first, after which each byte's low bit is set so the byte holds an odd number of 1s. That mirrors what PC-1 does, because it keeps exactly those 7 bits per byte and drops the parity bit. Distinct candidates therefore always produce distinct DES keys, and every generated key passes `des_check_parity`.

**The attack.** The attacker knows one pair `(P, C)` with `C = E_K(P)` and does not know `K`, so a candidate `K'` is correct when `E_K'(P) == C`. `des_brute_force` sweeps candidates sequentially, while `des_brute_force_parallel` splits the range into near-equal intervals with one thread each, and the thread that finds the key raises a flag the others poll so they stop without finishing their interval.

```bash
make benchmark                                              # defaults: n = 16,18,20
./build/bin/benchmark_bruteforce --bits 20,22 --workers 1,2,4 --repeats 5
./build/bin/benchmark_bruteforce --bits 16 --target 1000    # plant the key mid-space
./build/bin/benchmark_bruteforce --csv bruteforce.csv       # machine-readable output
```

Each `n` is measured twice, for two different reasons. The **full sweep** is timed against a ciphertext that no candidate in the space can produce, so no worker exits early and every thread count tests exactly 2ⁿ keys, which matters because comparing runs that did equal work is the only way speedup and efficiency mean anything. The **recovery** run is a real attack on a planted key, reporting where the key sat and how many candidates were tested before the workers stopped.

Measured on an Intel Core i3-1005G1 with 2 physical cores and 4 threads, `n = 20`, 3 repeats:

| Workers | Time [s] | Keys tested | Keys/s | Speedup | Efficiency |
|---:|---:|---:|---:|---:|---:|
| 1 | 2.6321 | 1048576 | 398386 | 1.00 | 1.00 |
| 2 | 1.3177 | 1048576 | 795778 | 2.00 | 1.00 |
| 4 | 1.2096 | 1048576 | 866901 | 2.18 | 0.54 |

Scaling to two workers is essentially perfect, while scaling to four is not, and the reason is the hardware rather than the partitioning. This CPU has only **2 physical cores**, so the third and fourth threads are SMT siblings that share the same execution units. A key search is pure integer work with no memory stalls for a sibling thread to fill, which is why the extra pair of threads adds only about 10 percent. Compare against your physical core count, not your logical one, and record your own CPU with `lscpu` when reporting numbers.

From the best measured rate of 881315 keys per second, the full space extrapolates to `T_max = 2⁵⁶/R ≈ 8.2e10 s ≈ 2591 years`, with `T_avg = 2⁵⁵/R ≈ 1295 years`, on one laptop. That number is the entire point, because the cipher is implemented correctly and is still broken: the attack divides perfectly across machines, this implementation favours clarity over speed, and dedicated hardware recovered a DES key in about 56 hours back in 1998.

---

# Project structure

```
include/
  des_tables.h         table declarations (IP, IP⁻¹, E, P, PC-1, PC-2, SHIFTS, SBOX)
  des_keyschedule.h    key schedule declaration
  des_feistel.h        Feistel function (f) and one full round (des_round)
  des.h                raw 64-bit block primitive: des_encrypt_block / des_decrypt_block
  des_api.h            single-block byte API: des_encrypt / des_decrypt / des_key_schedule / des_check_parity
  des_modes.h          modes layer: PKCS#7 padding, ECB, CBC
src/
  des_tables.c         table definitions, no logic
  des_keyschedule.c    PC-1 -> rotations -> PC-2
  des_feistel.c        E -> XOR -> S-boxes -> P
  des.c                IP -> 16 Feistel rounds -> IP⁻¹ (the actual cipher)
  des_api.c            byte to uint64_t conversion, length validation, parity check
  des_modes.c          padding plus ECB and CBC, built only on des_encrypt_block / des_decrypt_block
tests/
  test_des.c           known vector, key schedule, round trip, avalanche, invalid input, bit order,
                       padding, ECB/CBC round trips, IV effect, repeated-block contrast
examples/
  main.c               raw block primitive demo
experiments/
  modes_experiments.c  ECB vs CBC, IV effect, error propagation
benchmark_bruteForce/
  des_keyspace.h/.c    candidate -> 56 effective bits -> 64-bit key with odd parity
  des_brute_force.h/.c known-plaintext key search, sequential and threaded
  benchmark.c          throughput, speedup, efficiency, 2⁵⁶ extrapolation
  test_bruteforce.c    key space mapping and key recovery tests
Report_LAB02.pdf       the laboratory report
Makefile
```

Two directories appear once you build or run things, and neither is part of the sources: `build/` holds every compiled object and binary, while `results/` collects the output of `make experiments` and `make benchmark`. Removing both is always safe, because `make clean` deletes `build/` and the other targets recreate `results/` on demand.

The layers stay separate on purpose. `src/des.c` never includes `des_modes.h`, so no padding or chaining logic can reach the cipher core, and nothing under `src/` includes anything from `benchmark_bruteForce/`, so only the experiment binaries link against threads.

# Why it is built this way

Several choices exist specifically to avoid classes of bugs that are common in hand-rolled crypto code.

- **Fixed-width types everywhere** (`uint64_t`, `uint32_t` and `uint8_t` from `<stdint.h>`, never `int` or `long`). DES is defined bit by bit, and the size of a plain `int` can vary between machines. Shifting bits past the actual width of a variable is undefined behaviour in C, which means the compiler may produce anything at all, including silently wrong output with no warning. Fixed-width types pin the size down everywhere, so every bit operation behaves identically on any machine.
- **One `permute()` helper instead of six different functions.** `IP`, `IP⁻¹`, `E`, `P`, `PC-1` and `PC-2` all perform the same operation, namely picking bits from an input according to a table and reassembling them, only with different table sizes. Writing that once and driving it with data avoids six copies of the same indexing bug.
- **Every module knows only what it needs.** `des_tables` holds pure data and nothing else, `des_feistel` does not know how subkeys are derived because it simply receives one as a `uint64_t`, and the cipher core never includes the modes header. This is not merely style, since it keeps a bug in one layer from silently breaking the layer underneath it.
- **Round keys are wiped after use.** `des.c` zeroes the subkey buffer through a `volatile` pointer before returning, rather than with a plain `memset`. Compilers are allowed to delete a `memset` they can prove is never read again, which is a real and documented way for key material to stay sitting in memory instead of being erased.
- **Tables are transcribed exactly as FIPS 46-3 prints them**, numbered from 1 and most significant bit first, rather than pre-converted to C array offsets. A transcription error in one of these tables does not crash anything, because it silently produces a cipher that appears to work yet is not real DES and will not interoperate. Keeping the tables visually comparable to the specification makes such an error easy to catch by eye.

# Known limitations

- **No message authentication.** ECB and CBC provide confidentiality only, so nothing detects a modified ciphertext, as the error propagation experiment above demonstrates. Real use needs encrypt-then-MAC, or an AEAD mode that handles it for you.
- **Padding validation is not constant-time.** A caller that lets an attacker distinguish a padding error from a later failure builds a padding oracle.
- **Not constant-time in general.** S-box lookup timing can vary slightly with the values involved, so someone able to measure encryption time precisely could in theory learn key bits. No attempt is made to prevent that.
- Only ECB and CBC, with no CTR, CFB or OFB. The caller supplies the CBC IV, since there is no IV generation here and no helper that prepends it to the ciphertext.
- No detection of weak or semi-weak keys, a handful of which are known to behave unusually predictably.
- No Triple DES, which was the historical answer to DES's short key length.

These are acceptable for a project whose goal is to show how DES works internally, and they are listed here rather than left for someone to discover the hard way.

# References

- [FIPS PUB 46-3, Data Encryption Standard](https://csrc.nist.gov/pubs/fips/46-3/final)
- [NIST SP 800-38A, Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [RFC 5652 section 6.3, PKCS#7 padding](https://www.rfc-editor.org/rfc/rfc5652#section-6.3)

---

Made by **dtpollo**.
