/* PKCS#7 padding, ECB, and CBC, built only on des_encrypt_block /
 * des_decrypt_block. */

#include "des_modes.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "des.h"

/* Same MSB-first packing as des_api.c: spec bit 1 is the value's top bit. */
static uint64_t bytes_to_u64(const uint8_t bytes[DES_BLOCK_BYTES])
{
    uint64_t value = 0;

    for (int i = 0; i < DES_BLOCK_BYTES; ++i) {
        value = (value << 8) | bytes[i];
    }

    return value;
}

static void u64_to_bytes(uint64_t value, uint8_t bytes[DES_BLOCK_BYTES])
{
    for (int i = DES_BLOCK_BYTES - 1; i >= 0; --i) {
        bytes[i] = (uint8_t)(value & 0xFFu);
        value >>= 8;
    }
}

size_t des_padded_len(size_t data_len)
{
    return data_len + (DES_BLOCK_BYTES - (data_len % DES_BLOCK_BYTES));
}

des_status_t des_pkcs7_pad(const uint8_t *data, size_t data_len,
                           uint8_t *out, size_t out_cap, size_t *out_len)
{
    const size_t padded_len = des_padded_len(data_len);
    const uint8_t pad_byte  = (uint8_t)(padded_len - data_len);

    if (out_cap < padded_len) {
        return DES_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out, data, data_len);
    memset(&out[data_len], pad_byte, pad_byte);

    *out_len = padded_len;
    return DES_OK;
}

des_status_t des_pkcs7_unpad(const uint8_t *data, size_t data_len,
                             size_t *out_len)
{
    if (data_len == 0 || (data_len % DES_BLOCK_BYTES) != 0) {
        return DES_ERR_INVALID_LENGTH;
    }

    const uint8_t pad_byte = data[data_len - 1];

    if (pad_byte == 0 || pad_byte > DES_BLOCK_BYTES) {
        return DES_ERR_INVALID_PADDING;
    }

    for (size_t i = 0; i < pad_byte; ++i) {
        if (data[data_len - 1 - i] != pad_byte) {
            return DES_ERR_INVALID_PADDING;
        }
    }

    *out_len = data_len - pad_byte;
    return DES_OK;
}

des_status_t des_ecb_encrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (key_len != DES_KEY_BYTES) {
        return DES_ERR_INVALID_LENGTH;
    }

    size_t padded_len = 0;
    const des_status_t status = des_pkcs7_pad(plaintext, plaintext_len,
                                              out, out_cap, &padded_len);
    if (status != DES_OK) {
        return status;
    }

    const uint64_t key_value = bytes_to_u64(key);

    for (size_t offset = 0; offset < padded_len; offset += DES_BLOCK_BYTES) {
        const uint64_t block = bytes_to_u64(&out[offset]);
        u64_to_bytes(des_encrypt_block(block, key_value), &out[offset]);
    }

    *out_len = padded_len;
    return DES_OK;
}

des_status_t des_ecb_decrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (key_len != DES_KEY_BYTES
        || ciphertext_len == 0
        || (ciphertext_len % DES_BLOCK_BYTES) != 0) {
        return DES_ERR_INVALID_LENGTH;
    }

    if (out_cap < ciphertext_len) {
        return DES_ERR_BUFFER_TOO_SMALL;
    }

    const uint64_t key_value = bytes_to_u64(key);

    for (size_t offset = 0; offset < ciphertext_len; offset += DES_BLOCK_BYTES) {
        const uint64_t block = bytes_to_u64(&ciphertext[offset]);
        u64_to_bytes(des_decrypt_block(block, key_value), &out[offset]);
    }

    return des_pkcs7_unpad(out, ciphertext_len, out_len);
}

des_status_t des_cbc_encrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *iv, size_t iv_len,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (key_len != DES_KEY_BYTES || iv_len != DES_IV_BYTES) {
        return DES_ERR_INVALID_LENGTH;
    }

    size_t padded_len = 0;
    const des_status_t status = des_pkcs7_pad(plaintext, plaintext_len,
                                              out, out_cap, &padded_len);
    if (status != DES_OK) {
        return status;
    }

    const uint64_t key_value = bytes_to_u64(key);
    uint64_t previous = bytes_to_u64(iv); /* C_0 = IV */

    for (size_t offset = 0; offset < padded_len; offset += DES_BLOCK_BYTES) {
        const uint64_t plain = bytes_to_u64(&out[offset]);

        previous = des_encrypt_block(plain ^ previous, key_value);
        u64_to_bytes(previous, &out[offset]);
    }

    *out_len = padded_len;
    return DES_OK;
}

des_status_t des_cbc_decrypt(const uint8_t *key, size_t key_len,
                             const uint8_t *iv, size_t iv_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (key_len != DES_KEY_BYTES
        || iv_len != DES_IV_BYTES
        || ciphertext_len == 0
        || (ciphertext_len % DES_BLOCK_BYTES) != 0) {
        return DES_ERR_INVALID_LENGTH;
    }

    if (out_cap < ciphertext_len) {
        return DES_ERR_BUFFER_TOO_SMALL;
    }

    const uint64_t key_value = bytes_to_u64(key);
    uint64_t previous = bytes_to_u64(iv);

    for (size_t offset = 0; offset < ciphertext_len; offset += DES_BLOCK_BYTES) {
        /* Saved before the write, so `out` may alias `ciphertext`. */
        const uint64_t current = bytes_to_u64(&ciphertext[offset]);

        u64_to_bytes(des_decrypt_block(current, key_value) ^ previous, &out[offset]);
        previous = current;
    }

    return des_pkcs7_unpad(out, ciphertext_len, out_len);
}
