/*
 * Key schedule: PC-1 -> per-round left rotation -> PC-2 -> 16 subkeys.
 *
 *   64-bit key --PC-1--> C0 (28 bits) || D0 (28 bits)
 *   C_i, D_i rotate left by DES_SHIFTS[i] each round
 *   C_i || D_i --PC-2--> K_i (48 bits)
 */

#include "des_keyschedule.h"

#include <stdint.h>

#include "des_tables.h"

/* Picks bits from `input` according to `table` and reassembles them.
 * The spec numbers bits from 1, MSB first, hence (in_bits - table[i]). */
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
 * Circular left rotation on a 28-bit register. There's no native 28-bit
 * type, so bits shifted off the top are masked back in at the bottom:
 *
 *   mask = (1 << 28) - 1
 *        = 0001 0000 0000 0000 0000 0000 0000 0000   (1 << 28)
 *        - 0000 0000 0000 0000 0000 0000 0000 0001   (1)
 *        = 0000 1111 1111 1111 1111 1111 1111 1111   (28 ones)
 */
static uint32_t rotate_left_28(uint32_t half, unsigned amount)
{
    const uint32_t mask = (UINT32_C(1) << DES_KEY_HALF_BITS) - 1;

    /* amount is always 1 or 2, see DES_SHIFTS. */
    return ((half << amount) | (half >> (DES_KEY_HALF_BITS - amount))) & mask;
}

void des_generate_round_keys(uint64_t key, uint64_t round_keys[static DES_ROUNDS])
{
    /* PC-1 drops the 8 parity bits, leaving 56. */
    const uint64_t permuted_key = permute(key, DES_PC1,
                                          DES_KEY_BITS_EFFECTIVE, DES_KEY_BITS);

    const uint32_t half_mask = (UINT32_C(1) << DES_KEY_HALF_BITS) - 1;

    /* Split into C (top 28 bits) and D (bottom 28 bits). */
    uint32_t c = (uint32_t)((permuted_key >> DES_KEY_HALF_BITS) & half_mask);
    uint32_t d = (uint32_t)(permuted_key & half_mask);

    for (unsigned round = 0; round < DES_ROUNDS; ++round) {
        /* Rotations stack up round over round, not reset to C0/D0 each time. */
        c = rotate_left_28(c, DES_SHIFTS[round]);
        d = rotate_left_28(d, DES_SHIFTS[round]);

        /* PC-2 treats C_i || D_i as a single 56-bit value. */
        const uint64_t combined = ((uint64_t)c << DES_KEY_HALF_BITS) | (uint64_t)d;

        round_keys[round] = permute(combined, DES_PC2,
                                    DES_SUBKEY_BITS, DES_KEY_BITS_EFFECTIVE);
    }
}
