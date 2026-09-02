/*
 * Public API for the DES block cipher.
 *
 * WARNING: DES is broken today. Its 56-bit effective key falls to brute
 * force on modern hardware; NIST withdrew it in 2005. Educational use only
 * -- for real encryption use AES-GCM or ChaCha20-Poly1305 through an
 * audited library (libsodium, OpenSSL).
 *
 * This header covers only ONE 64-bit block: no padding, no IV, no chaining.
 * That's the job of block cipher modes (see des_modes.h), not this file.
 * Encrypting several blocks back to back with just this API is, by
 * definition, ECB mode -- it leaks patterns in the plaintext and shouldn't
 * be used that way for real data.
 */

#ifndef DES_H
#define DES_H

#include <stdint.h>

#include "des_tables.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Encrypts one 64-bit block.
 *
 * block  Plaintext as a 64-bit integer; bit 1 of the spec is this value's
 *        most significant bit.
 * key    64-bit key; the 8 parity bits are ignored.
 *
 * Pure and reentrant: no global state, safe to call from multiple threads.
 */
uint64_t des_encrypt_block(uint64_t block, uint64_t key);

/*
 * Decrypts one 64-bit block. Runs the exact same Feistel network as
 * des_encrypt_block, just with subkeys applied in reverse order (K16..K1
 * instead of K1..K16).
 *
 * Always true: des_decrypt_block(des_encrypt_block(block, key), key) == block
 */
uint64_t des_decrypt_block(uint64_t block, uint64_t key);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DES_H */
