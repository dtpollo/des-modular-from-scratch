/* Derives the 16 round subkeys from the 64-bit key. */

#ifndef DES_KEYSCHEDULE_H
#define DES_KEYSCHEDULE_H

#include <stdint.h>

#include "des_tables.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * key         64-bit key. The 8 parity bits are ignored (PC-1 never
 *             selects them), so only 56 bits actually matter.
 * round_keys  Output buffer, exactly DES_ROUNDS entries. Each subkey uses
 *             its low 48 bits; the top 16 bits are always zero.
 */
void des_generate_round_keys(uint64_t key, uint64_t round_keys[static DES_ROUNDS]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DES_KEYSCHEDULE_H */
