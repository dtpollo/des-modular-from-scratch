/* Byte-buffer wrapper around the block primitive, with length validation. */

#include "des_api.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "des.h"
#include "des_keyschedule.h"

/* Packs 8 bytes into a uint64_t, most significant byte first -- matches how
 * des_encrypt_block treats spec bit 1 as its top bit. */
static uint64_t bytes_to_u64(const uint8_t bytes[DES_BLOCK_BYTES])
{
    uint64_t value = 0;

    for (int i = 0; i < DES_BLOCK_BYTES; ++i) {
        value = (value << 8) | bytes[i];
    }

    return value;
}

/* Reverses bytes_to_u64. */
static void u64_to_bytes(uint64_t value, uint8_t bytes[DES_BLOCK_BYTES])
{
    for (int i = DES_BLOCK_BYTES - 1; i >= 0; --i) {
        bytes[i] = (uint8_t)(value & 0xFFu);
        value >>= 8;
    }
}

des_status_t des_encrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *plaintext, size_t plaintext_len,
                         uint8_t out[DES_BLOCK_BYTES])
{
    if (key_len != DES_KEY_BYTES || plaintext_len != DES_BLOCK_BYTES) {
        return DES_ERR_INVALID_LENGTH;
    }

    const uint64_t cipher_block = des_encrypt_block(bytes_to_u64(plaintext),
                                                    bytes_to_u64(key));
    u64_to_bytes(cipher_block, out);
    return DES_OK;
}

des_status_t des_decrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *ciphertext, size_t ciphertext_len,
                         uint8_t out[DES_BLOCK_BYTES])
{
    if (key_len != DES_KEY_BYTES || ciphertext_len != DES_BLOCK_BYTES) {
        return DES_ERR_INVALID_LENGTH;
    }

    const uint64_t plain_block = des_decrypt_block(bytes_to_u64(ciphertext),
                                                   bytes_to_u64(key));
    u64_to_bytes(plain_block, out);
    return DES_OK;
}

des_status_t des_key_schedule(const uint8_t *key, size_t key_len,
                              uint64_t round_keys[static DES_ROUNDS])
{
    if (key_len != DES_KEY_BYTES) {
        return DES_ERR_INVALID_LENGTH;
    }

    des_generate_round_keys(bytes_to_u64(key), round_keys);
    return DES_OK;
}

des_status_t des_check_parity(const uint8_t *key, size_t key_len, bool *is_valid)
{
    if (key_len != DES_KEY_BYTES) {
        return DES_ERR_INVALID_LENGTH;
    }

    bool all_odd = true;

    for (size_t i = 0; i < DES_KEY_BYTES; ++i) {
        unsigned ones = 0;
        uint8_t byte = key[i];

        while (byte != 0) {
            ones += (unsigned)(byte & 1u);
            byte = (uint8_t)(byte >> 1);
        }

        if ((ones % 2u) == 0u) {
            all_odd = false;
            break;
        }
    }

    *is_valid = all_odd;
    return DES_OK;
}
