/*
 * The DES block cipher: IP -> 16 Feistel rounds -> IP^-1.
 *
 * Each round:
 *     L_i = R_{i-1}
 *     R_i = L_{i-1} XOR f(R_{i-1}, K_i)
 *
 * f() doesn't need to be reversible: undoing a round only needs K_i, since
 * L_{i-1} = R_i XOR f(L_i, K_i). That's the whole reason encrypt and
 * decrypt below share the same code, just with subkeys applied in reverse
 * order.
 *
 * This file never includes des_modes.h -- no padding, IV, or chaining here,
 * only the raw 64-bit block transform.
 */

#include "des.h"

#include <stdint.h>
#include <string.h>

#include "des_feistel.h"
#include "des_keyschedule.h"
#include "des_tables.h"

#define DES_HALF_MASK UINT64_C(0xFFFFFFFF)

/* Which way to walk the subkeys. */
typedef enum {
    DES_KEY_ORDER_FORWARD = 0, /* K1..K16: encrypt */
    DES_KEY_ORDER_REVERSE = 1  /* K16..K1: decrypt */
} des_key_order_t;

/* Same permute() used across the codebase: picks bits from `input` per
 * `table`. The spec numbers bits from 1, MSB first. */
static uint64_t permute(uint64_t input, const uint8_t *table,
                        unsigned out_bits, unsigned in_bits)
{
    uint64_t output = 0;

    for (unsigned i = 0; i < out_bits; ++i) {
        const uint64_t bit = (input >> (in_bits - table[i])) & UINT64_C(1);
        output = (output << 1) | bit;
    }

    return output;
}

/*
 * Zeroes memory through a volatile pointer instead of plain memset.
 * A compiler is allowed to delete a memset it can prove is never read
 * again ("dead store elimination") -- writing through volatile stops that,
 * so key material doesn't linger in memory longer than needed.
 */
static void secure_zero(void *buffer, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)buffer;

    while (length-- > 0) {
        *p++ = 0;
    }
}

/* Shared core for both encrypt and decrypt; only `order` differs. */
static uint64_t des_process_block(uint64_t block,
                                  const uint64_t round_keys[static DES_ROUNDS],
                                  des_key_order_t order)
{
    const uint64_t permuted = permute(block, DES_IP, DES_BLOCK_BITS, DES_BLOCK_BITS);

    uint32_t left  = (uint32_t)(permuted >> DES_HALF_BLOCK_BITS);
    uint32_t right = (uint32_t)(permuted & DES_HALF_MASK);

    for (unsigned round = 0; round < DES_ROUNDS; ++round) {
        const unsigned index = (order == DES_KEY_ORDER_REVERSE)
                             ? (DES_ROUNDS - 1 - round)
                             : round;

        const uint32_t previous_right = right;

        /* R_i = L_{i-1} XOR f(R_{i-1}, K_i);  L_i = R_{i-1} */
        right = left ^ des_feistel_f(right, round_keys[index]);
        left  = previous_right;
    }

    /* Final swap: output is R16 || L16, not L16 || R16. This swap is what
     * makes the network symmetric between encrypt and decrypt. */
    const uint64_t preoutput = ((uint64_t)right << DES_HALF_BLOCK_BITS)
                             | (uint64_t)left;

    return permute(preoutput, DES_IP_INV, DES_BLOCK_BITS, DES_BLOCK_BITS);
}

/* Derives the subkeys, runs the block through, wipes the subkeys. */
static uint64_t des_run(uint64_t block, uint64_t key, des_key_order_t order)
{
    uint64_t round_keys[DES_ROUNDS];

    des_generate_round_keys(key, round_keys);
    const uint64_t result = des_process_block(block, round_keys, order);

    secure_zero(round_keys, sizeof round_keys);

    return result;
}

uint64_t des_encrypt_block(uint64_t block, uint64_t key)
{
    return des_run(block, key, DES_KEY_ORDER_FORWARD);
}

uint64_t des_decrypt_block(uint64_t block, uint64_t key)
{
    return des_run(block, key, DES_KEY_ORDER_REVERSE);
}
