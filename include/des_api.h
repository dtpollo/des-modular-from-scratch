/*
 * Public byte-oriented API for the DES library.
 *
 * des.h exposes the raw 64-bit block primitive (des_encrypt_block /
 * des_decrypt_block). This header wraps it with a byte-buffer interface
 * that validates input length explicitly instead of assuming exactly 8
 * bytes were passed -- the shape most callers actually want, and the one
 * that lets malformed input be rejected instead of silently misread.
 *
 * Named des_encrypt/des_decrypt rather than des_encrypt_block/
 * des_decrypt_block to avoid colliding with the existing 64-bit primitive
 * in des.h -- C has no function overloading.
 */

#ifndef DES_API_H
#define DES_API_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "des_tables.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DES_BLOCK_BYTES 8
#define DES_KEY_BYTES   8

typedef enum {
    DES_OK = 0,
    DES_ERR_INVALID_LENGTH = -1
} des_status_t;

/* Encrypts exactly 8 bytes of plaintext with an 8-byte key.
 * Returns DES_ERR_INVALID_LENGTH if key_len or plaintext_len isn't 8. */
des_status_t des_encrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t out[DES_BLOCK_BYTES]);

/* Decrypts exactly 8 bytes of ciphertext with an 8-byte key. */
des_status_t des_decrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         uint8_t out[DES_BLOCK_BYTES]);

/* Derives the 16 round subkeys from an 8-byte key. */
des_status_t des_key_schedule(const uint8_t *key, size_t key_len,
                              uint64_t round_keys[static DES_ROUNDS]);

/*
 * Checks DES's per-byte odd-parity convention: each key byte's 8 bits
 * (7 data bits + 1 parity bit) should contain an odd number of 1 bits.
 * This is a legacy error-detection check inherited from old hardware, not
 * a security property -- DES ignores these bits during encryption either
 * way (see PC-1 in des_tables.c).
 *
 * *is_valid is only written when the return value is DES_OK.
 */
des_status_t des_check_parity(const uint8_t *key, size_t key_len, bool *is_valid);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DES_API_H */
