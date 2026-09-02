/* The Feistel round function f(R, K). Knows nothing about how subkeys are
 * derived -- it just takes one as a plain 48-bit value. */

#ifndef DES_FEISTEL_H
#define DES_FEISTEL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * f(half_block, round_key):
 *   1. Expand E:      32 -> 48 bits.
 *   2. XOR with round_key (the only place the key enters the cipher).
 *   3. Substitute:    8 S-boxes, 48 -> 32 bits.
 *   4. Permute P:     spreads the result for the next round.
 *
 * Returns the 32 bits to XOR into the other half of the block.
 */
uint32_t des_feistel_f(uint32_t half_block, uint64_t round_key);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DES_FEISTEL_H */
