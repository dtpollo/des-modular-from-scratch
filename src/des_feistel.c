/* Feistel round function: expand (E) -> XOR with subkey -> S-boxes -> permute (P). */

#include "des_feistel.h"

#include <stdint.h>

#include "des_tables.h"

#define DES_SUBKEY_MASK ((UINT64_C(1) << DES_SUBKEY_BITS) - 1)

#define DES_SBOX_INPUT_BITS  6
#define DES_SBOX_OUTPUT_BITS 4

/* Same permute() used across the codebase: picks bits from `input` per
 * `table`. The spec numbers bits from 1, MSB first. */
static uint64_t permute(uint64_t input, const uint8_t *table, unsigned out_bits, unsigned in_bits)
{
    uint64_t output = 0;

    for (unsigned i = 0; i < out_bits; ++i) {
        const uint64_t bit = (input >> (in_bits - table[i])) & UINT64_C(1);
        output = (output << 1) | bit;
    }

    return output;
}

/*
 * Runs the 48 expanded bits through the 8 S-boxes: 6 bits in, 4 bits out
 * each. Each 6-bit chunk splits like this:
 *
 *     bit:    5   4   3   2   1   0
 *            row  \--- col ---/  row
 *
 * Bits 5 and 0 (the two outer bits) pick the row (0-3).
 * Bits 4-1 (the four middle bits) pick the column (0-15).
 *
 * The outer bits are exactly the ones E duplicated from the neighboring
 * 4-bit group, so a single input bit changes two S-boxes at once -- that's
 * what makes the avalanche effect spread quickly across rounds.
 */
static uint32_t substitute(uint64_t expanded)
{
    uint32_t output = 0;

    for (unsigned box = 0; box < DES_SBOX_COUNT; ++box) {
        /* Chunks are read left to right: box 0 gets the top 6 bits of 48. */
        const unsigned shift = DES_SUBKEY_BITS - DES_SBOX_INPUT_BITS - (box * DES_SBOX_INPUT_BITS);

        /* Save low 6 bits*/
        const uint8_t chunk = (uint8_t)((expanded >> shift) & 0x3Fu);

        const unsigned row = (unsigned)(((chunk & 0x20u) >> 4) | (chunk & 0x01u));
        const unsigned col = (unsigned)((chunk >> 1) & 0x0Fu);

        output = (output << DES_SBOX_OUTPUT_BITS) | DES_SBOX[box][row][col];
    }

    return output;
}

uint32_t des_feistel_f(uint32_t half_block, uint64_t round_key)
{
    /* 1. Expand 32 -> 48 bits. */
    const uint64_t expanded = permute((uint64_t)half_block, DES_E, DES_SUBKEY_BITS, DES_HALF_BLOCK_BITS);

    /* 2. Mix in the key -- the only place it touches the cipher. */
    const uint64_t mixed = expanded ^ (round_key & DES_SUBKEY_MASK);

    /* 3. Substitute: 48 -> 32 bits, the only non-linear step. */
    const uint32_t substituted = substitute(mixed);

    /* 4. Spread each S-box's output bits toward different boxes next round. */
    return (uint32_t)permute((uint64_t)substituted, DES_P,
                             DES_HALF_BLOCK_BITS, DES_HALF_BLOCK_BITS);
}

des_half_pair_t des_round(uint32_t left, uint32_t right, uint64_t round_key)
{
    des_half_pair_t next;

    next.left  = right;
    next.right = left ^ des_feistel_f(right, round_key);

    return next;
}
