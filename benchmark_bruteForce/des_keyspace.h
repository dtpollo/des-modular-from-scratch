/*
 * Controlled key space for the brute-force experiments.
 *
 * Searching all 2^56 effective keys is out of scope, so a run varies only
 * the low `unknown_bits` of the 56 effective key bits and fixes the rest to
 * a known prefix. Every candidate goes through the same mapping:
 *
 *     candidate (n bits) -> 56 effective bits -> 64-bit DES key
 *
 * The 56 effective bits are laid out 7 per key byte, most significant group
 * first, and each byte's low bit is filled in as an odd-parity bit. That
 * mirrors PC-1, which keeps exactly those 7 bits per byte and drops the
 * parity bit -- so distinct candidates always give distinct DES keys, and
 * every generated key satisfies the parity convention des_check_parity
 * expects.
 *
 * This is experimental code, not part of the cipher: nothing under src/
 * includes it.
 */

#ifndef DES_KEYSPACE_H
#define DES_KEYSPACE_H

#include <stdint.h>

#include "des_tables.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Past this width a search stops being something to run and becomes
 * something to extrapolate. */
#define DES_KEYSPACE_MAX_BITS 32

typedef struct {
    unsigned unknown_bits; /* n: the bits a search varies, 1..DES_KEYSPACE_MAX_BITS */
    uint64_t fixed_prefix; /* the 56 - n known bits above them, right-aligned */
} des_keyspace_t;

/* 2^unknown_bits. */
uint64_t des_keyspace_size(const des_keyspace_t *space);

/* candidate -> 56 effective bits -> 64-bit DES key with odd parity. */
uint64_t des_keyspace_key(const des_keyspace_t *space, uint64_t candidate);

/* Spreads 56 effective bits over 8 bytes, 7 data bits each, and sets every
 * byte's low bit so the byte holds an odd number of 1s. */
uint64_t des_key_with_parity(uint64_t effective_bits);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DES_KEYSPACE_H */
