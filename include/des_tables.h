/* DES standard tables (FIPS 46-3). Pure data, no logic -- these never
 * change, so they live apart from the code that uses them. */

#ifndef DES_TABLES_H
#define DES_TABLES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Table sizes, shared by every module. */
#define DES_ROUNDS             16
#define DES_BLOCK_BITS         64
#define DES_KEY_BITS           64
#define DES_KEY_BITS_EFFECTIVE 56 /* 64 minus the 8 parity bits */
#define DES_HALF_BLOCK_BITS    32
#define DES_SUBKEY_BITS        48
#define DES_KEY_HALF_BITS      28 /* C and D registers in the key schedule */

#define DES_SBOX_COUNT 8
#define DES_SBOX_ROWS  4
#define DES_SBOX_COLS  16

/* Note: the spec numbers bits from 1, MSB first. Tables below use that same
 * numbering (not 0-based C indexing) so they can be checked by eye against
 * FIPS 46-3. The conversion to a bit-shift happens in permute(). */

/* Initial permutation, applied before round 1. */
extern const uint8_t DES_IP[DES_BLOCK_BITS];

/* Final permutation, exact inverse of DES_IP. */
extern const uint8_t DES_IP_INV[DES_BLOCK_BITS];

/* Expansion: 32 -> 48 bits. Duplicates edge bits so each one feeds two
 * S-boxes instead of one. */
extern const uint8_t DES_E[DES_SUBKEY_BITS];

/* Permutation applied to the S-box output; spreads each box's 4 bits
 * toward different boxes in the next round. */
extern const uint8_t DES_P[DES_HALF_BLOCK_BITS];

/* PC-1: 64 -> 56 bits. Drops the 8 parity bits, splits the rest into C0/D0. */
extern const uint8_t DES_PC1[DES_KEY_BITS_EFFECTIVE];

/* PC-2: 56 -> 48 bits. Compresses C_i || D_i into the round subkey. */
extern const uint8_t DES_PC2[DES_SUBKEY_BITS];

/* Left-rotation amount per round for C and D. Sums to 28, so after round 16
 * both registers are back to their starting value. */
extern const uint8_t DES_SHIFTS[DES_ROUNDS];

/* The 8 substitution boxes -- DES's only non-linear step. */
extern const uint8_t DES_SBOX[DES_SBOX_COUNT][DES_SBOX_ROWS][DES_SBOX_COLS];

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DES_TABLES_H */
