/*
 * Known-plaintext exhaustive key search over a controlled key space.
 *
 * The attacker knows one pair (P, C) with C = E_K(P) and not K. A candidate
 * K' is correct when E_K'(P) == C, so the search is a real sweep: derive the
 * key for each candidate, encrypt P, compare. Both functions walk candidates
 * in [start, end) and stop at the first match.
 */

#ifndef DES_BRUTE_FORCE_H
#define DES_BRUTE_FORCE_H

#include <stdbool.h>
#include <stdint.h>

#include "des_keyspace.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Enough for any core count this lab runs on, and it keeps the worker
 * bookkeeping on the stack. */
#define DES_ATTACK_MAX_WORKERS 64

typedef struct {
    bool     found;
    uint64_t candidate;         /* the matching candidate, when found */
    uint64_t key;               /* the 64-bit DES key it maps to */
    uint64_t candidates_tested; /* summed over every worker */
} des_attack_result_t;

des_attack_result_t des_brute_force(const des_keyspace_t *space,
                                    uint64_t plaintext, uint64_t ciphertext,
                                    uint64_t start, uint64_t end);

/*
 * The same search split into `workers` near-equal intervals, one thread
 * each, clamped to DES_ATTACK_MAX_WORKERS. The thread that finds the key
 * raises a flag the others poll, so they stop without finishing their
 * interval -- which is why candidates_tested is usually below the full
 * range.
 */
des_attack_result_t des_brute_force_parallel(const des_keyspace_t *space,
                                             uint64_t plaintext, uint64_t ciphertext,
                                             uint64_t start, uint64_t end,
                                             unsigned workers);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DES_BRUTE_FORCE_H */
