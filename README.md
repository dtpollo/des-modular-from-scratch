# DES in C

From-scratch **DES** block cipher in C11, with **PKCS#7 padding, ECB and CBC** on top, plus a **parallel brute-force key search** that measures what its 56-bit key costs an attacker.

> ⚠️ **DES is broken.** Its 56-bit effective key falls to brute force, and NIST withdrew it in 2005. Educational use only. For real data use AES-GCM or ChaCha20-Poly1305 from an audited library.

Full write-up, experiments and measurements: [`Report_LAB02.pdf`](Report_LAB02.pdf).

## Requirements

C11 compiler (GCC or Clang) and `make`. No external dependencies. The brute-force programs also use POSIX threads (`-pthread`), included with glibc and Clang.

## Build and run

```bash
make test           # both test suites: 66 checks for cipher and modes, 18 for the attack
make experiments    # ECB vs CBC, effect of the IV, error propagation
make benchmark      # throughput, speedup, efficiency, 2^56 extrapolation
make examples       # raw block primitive demo
make help           # all targets
```

Encrypt your own text with the block demo:

```bash
./build/bin/des_demo "this is my message"
```

Run the key search with your own parameters:

```bash
./build/bin/benchmark_bruteforce --bits 16,18,20 --workers 1,2,4 --repeats 3
./build/bin/benchmark_bruteforce --bits 16 --target 1000     # plant the key mid-space
./build/bin/benchmark_bruteforce --csv bruteforce.csv        # machine-readable output
```

`build/` and `results/` are generated. `make clean` removes `build/`, and the other targets recreate `results/`.

## The three layers

| Header | Use it for |
|---|---|
| `des_modes.h` | **Messages of any length: padding, ECB, CBC.** What most callers want |
| `des_api.h` | One 8-byte block on byte buffers, with length validation |
| `des.h` | The raw `uint64_t` block primitive |

## Using ECB and CBC

Key, block and IV are all exactly **8 bytes** (`DES_KEY_BYTES`, `DES_BLOCK_BYTES`, `DES_IV_BYTES`); anything else is rejected. Nothing allocates, so you pass the buffer and its capacity and get the written length back through `out_len`. Encryption needs `des_padded_len(plaintext_len)` bytes of room, decryption needs `ciphertext_len`.

Returns `DES_OK`, `DES_ERR_INVALID_LENGTH`, `DES_ERR_INVALID_PADDING` (usually a wrong key) or `DES_ERR_BUFFER_TOO_SMALL`. Always check it, and note `out_len` is only written on `DES_OK`.

```c
#include <string.h>
#include "des_modes.h"

const uint8_t key[DES_KEY_BYTES] = { 0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1 };
const uint8_t iv[DES_IV_BYTES]   = { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88 };
const char *msg = "Hola, DES desde C!";

uint8_t cipher[64], plain[64];
size_t cipher_len = 0, plain_len = 0;

/* CBC, the one to prefer. ECB is the same call without the iv arguments. */
if (des_cbc_encrypt(key, DES_KEY_BYTES, iv, DES_IV_BYTES,
                    (const uint8_t *)msg, strlen(msg),
                    cipher, sizeof cipher, &cipher_len) != DES_OK) return 1;
/* 76CA4BD63050221141A90BC6D00A58DB44DC3889B2C7692B */

if (des_cbc_decrypt(key, DES_KEY_BYTES, iv, DES_IV_BYTES,
                    cipher, cipher_len, plain, sizeof plain, &plain_len) != DES_OK) return 1;
/* plain[0 .. plain_len-1] == msg */
```

Padding is applied on encryption and validated and stripped on decryption, so `out_len` is the true plaintext length. `des_pkcs7_pad` and `des_pkcs7_unpad` are exposed if you want to pad separately. PKCS#7 appends `p` bytes of value `p`, and since `p` is never zero a message that is already a multiple of 8 gains a whole extra block, which is what makes the padding unambiguous to remove.

### The IV

1. Exactly 8 bytes.
2. Not secret, so send it with the ciphertext, usually prepended.
3. Unpredictable and fresh per message. Reuse brings back the determinism CBC removes.
4. Not generated here. Use `getrandom(iv, sizeof iv, 0)` rather than `rand()`.

### Why not ECB

ECB encrypts each block alone, so equal plaintext blocks give equal ciphertext blocks. Encrypting `ABCDEFGHABCDEFGHABCDEFGHABCDEFGH` returns the block `0EE11BD2808EF0A1` four times, leaking the structure of the message. CBC chains each block into the next (`C₀ = IV`, `Cᵢ = E_K(Pᵢ ⊕ Cᵢ₋₁)`) and returns five distinct blocks. Use ECB only to observe that effect.

Both modes match `openssl enc -des-ecb` and `-des-cbc` byte for byte.

## Brute-force search

A candidate key `K'` is tested against one known pair `(P, C)` and accepted when `E_K'(P) == C`. Only the low `n` bits of the 56 effective key bits vary, while the rest stay at a known prefix, so `candidate -> 56 effective bits -> 64-bit key` with odd parity per byte. `des_brute_force` sweeps sequentially and `des_brute_force_parallel` splits the range across threads, stopping the others once one finds the key.

Measured on an Intel Core i3-1005G1 (2 physical cores, 4 threads): about 395k keys/s on one core, speedup 1.99 at two workers and 2.20 at four, since the extra two threads are SMT siblings sharing the same execution units. At the best rate of 881315 keys/s the full 2⁵⁶ space extrapolates to roughly 2591 years, or 1295 on average, on this one laptop.

## Structure

```
include/   public headers (des.h, des_api.h, des_modes.h, tables, key schedule, Feistel)
src/       the cipher, the byte API, and the modes layer
tests/     test_des.c, 66 checks
examples/  raw block primitive demo
experiments/         ECB vs CBC, IV effect, error propagation
benchmark_bruteForce/ key space, sequential and parallel search, benchmark, 18 checks
```

The layers stay separate: `src/des.c` never includes `des_modes.h`, and nothing in `src/` depends on `benchmark_bruteForce/`, so only the attack binaries link threads.

## Limitations

- **No authentication.** ECB and CBC give confidentiality only, so a modified ciphertext goes undetected. Real use needs encrypt-then-MAC or an AEAD mode.
- **Not constant-time**, including the padding check, so a caller that leaks which error occurred creates a padding oracle.
- Only ECB and CBC. No CTR, CFB, OFB, Triple DES, or weak-key detection.

## References

- [FIPS PUB 46-3, Data Encryption Standard](https://csrc.nist.gov/pubs/fips/46-3/final)
- [NIST SP 800-38A, Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [RFC 5652 section 6.3, PKCS#7 padding](https://www.rfc-editor.org/rfc/rfc5652#section-6.3)

---

Made by **dtpollo**.
