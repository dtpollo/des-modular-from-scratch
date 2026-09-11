/*
 * Block cipher modes: PKCS#7 padding, ECB, and CBC.
 *
 * Encryption comes only from des.h (des_encrypt_block / des_decrypt_block);
 * des_api.h supplies the shared status type and the byte-size constants.
 * The cipher core never includes this file, so a bug in a mode or in the
 * padding can't reach the algorithm underneath it.
 *
 * WARNING: ECB is implemented for the contrast with CBC. Identical
 * plaintext blocks always produce identical ciphertext blocks, so it leaks
 * the structure of the message -- don't use it for real multi-block data.
 *
 * Output buffers are caller-allocated, like the rest of the library:
 * nothing here allocates. Encryption writes des_padded_len(plaintext_len)
 * bytes; decryption writes ciphertext_len bytes.
 *
 * *out_len is written only on DES_OK. On any error the contents of `out`
 * are unspecified -- a decrypt that fails its padding check has already
 * written the decrypted bytes there.
 */

#ifndef DES_MODES_H
#define DES_MODES_H

#include <stddef.h>
#include <stdint.h>

#include "des_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DES_IV_BYTES 8

/* Bytes des_pkcs7_pad writes for a data_len-byte message. There is always
 * at least one padding byte, so a block-aligned message gains a whole
 * extra block. */
size_t des_padded_len(size_t data_len);

/* Appends p copies of the byte whose value is p, where p is the number of
 * bytes needed to fill the final block (1-8, never 0). */
des_status_t des_pkcs7_pad(const uint8_t *data, size_t data_len,
                           uint8_t *out, size_t out_cap, size_t *out_len);

/*
 * Validates the padding on `data` and reports the length without it in
 * *out_len; `data` itself is left unchanged. Returns
 * DES_ERR_INVALID_PADDING if the trailing bytes aren't well formed.
 *
 * Not constant-time. A caller that lets an attacker tell this error apart
 * from a later failure builds a padding oracle -- real CBC use needs an
 * authentication tag (encrypt-then-MAC), not just this check.
 */
des_status_t des_pkcs7_unpad(const uint8_t *data, size_t data_len,
                             size_t *out_len);

/* C_i = E_K(P_i). Pads automatically; *out_len is the ciphertext length. */
des_status_t des_ecb_encrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *out, size_t out_cap, size_t *out_len);

/* P_i = D_K(C_i). Validates and strips the padding, so *out_len is the
 * plaintext length and `out` still holds the padding bytes past it. */
des_status_t des_ecb_decrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             uint8_t *out, size_t out_cap, size_t *out_len);

/* C_0 = IV, C_i = E_K(P_i XOR C_{i-1}). The IV must be fresh and
 * unpredictable per message, but it isn't secret -- it travels with the
 * ciphertext. */
des_status_t des_cbc_encrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *iv, size_t iv_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *out, size_t out_cap, size_t *out_len);

/* P_i = D_K(C_i) XOR C_{i-1}. */
des_status_t des_cbc_decrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *iv, size_t iv_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DES_MODES_H */
