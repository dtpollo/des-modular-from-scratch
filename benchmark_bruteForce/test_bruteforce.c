/*
 * Test suite for the brute-force experiment code.
 *
 * Covers the lab's required brute-force check -- plant a key inside a small
 * controlled space and verify the search recovers it -- plus the candidate
 * -> key mapping it depends on: parity, injectivity, and space size. Kept
 * separate from tests/test_des.c so the cipher's own suite stays free of
 * experimental code. Same tiny counter, no test framework.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "des.h"
#include "des_api.h"
#include "des_brute_force.h"
#include "des_keyschedule.h"
#include "des_keyspace.h"

#define KNOWN_PLAINTEXT UINT64_C(0x0123456789ABCDEF)

static unsigned g_checks_run;
static unsigned g_checks_failed;

static void expect_u64(const char *label, uint64_t actual, uint64_t expected)
{
    ++g_checks_run;

    if (actual == expected) {
        printf("  [ ok ] %s\n", label);
    } else {
        ++g_checks_failed;
        printf("  [FAIL] %s\n", label);
        printf("         expected: %" PRIu64 "\n", expected);
        printf("         actual:   %" PRIu64 "\n", actual);
    }
}

static void expect_true(const char *label, int condition)
{
    ++g_checks_run;

    if (condition) {
        printf("  [ ok ] %s\n", label);
    } else {
        ++g_checks_failed;
        printf("  [FAIL] %s\n", label);
    }
}

static bool key_has_odd_parity(uint64_t key)
{
    uint8_t bytes[DES_KEY_BYTES];
    bool valid = false;

    for (int i = DES_KEY_BYTES - 1; i >= 0; --i) {
        bytes[i] = (uint8_t)(key & 0xFFu);
        key >>= 8;
    }

    return des_check_parity(bytes, DES_KEY_BYTES, &valid) == DES_OK && valid;
}

/* ------------------------------------------------------------------ */
/* Key space: candidate -> 56 effective bits -> 64-bit DES key         */
/* ------------------------------------------------------------------ */

static void test_keyspace(void)
{
    puts("Controlled key space");

    const des_keyspace_t space = { 12, UINT64_C(0x2A5C3) };
    const uint64_t size = des_keyspace_size(&space);

    expect_u64("size is 2^n", size, UINT64_C(4096));

    int parity_ok = 1;
    int in_range_ok = 1;

    for (uint64_t candidate = 0; candidate < size; ++candidate) {
        const uint64_t key = des_keyspace_key(&space, candidate);

        if (!key_has_odd_parity(key)) {
            parity_ok = 0;
        }
        if (key == 0) {
            in_range_ok = 0;
        }
    }

    expect_true("every generated key satisfies the odd-parity convention", parity_ok);
    expect_true("no candidate maps to an all-zero key", in_range_ok);

    /* Distinct candidates must give distinct keys, or the search would be
     * testing the same key twice and skipping another. */
    int injective = 1;
    for (uint64_t candidate = 1; candidate < size; ++candidate) {
        if (des_keyspace_key(&space, candidate) == des_keyspace_key(&space, candidate - 1)) {
            injective = 0;
            break;
        }
    }
    expect_true("distinct candidates map to distinct keys", injective);

    /* Candidates past the width wrap instead of leaking into the prefix. */
    expect_u64("a candidate above the space wraps to its low n bits",
               des_keyspace_key(&space, size + 7), des_keyspace_key(&space, 7));

    /* The parity bits carry no key material, so PC-1 ignores them: two keys
     * differing only there must produce the same subkeys. */
    uint64_t round_keys_a[DES_ROUNDS];
    uint64_t round_keys_b[DES_ROUNDS];
    const uint64_t key = des_keyspace_key(&space, 1234);

    des_generate_round_keys(key, round_keys_a);
    des_generate_round_keys(key ^ UINT64_C(0x0101010101010101), round_keys_b);

    int same_schedule = 1;
    for (unsigned i = 0; i < DES_ROUNDS; ++i) {
        if (round_keys_a[i] != round_keys_b[i]) {
            same_schedule = 0;
        }
    }
    expect_true("flipping every parity bit leaves the key schedule unchanged", same_schedule);

    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Sequential search                                                   */
/* ------------------------------------------------------------------ */

static void test_sequential_search(void)
{
    puts("Sequential exhaustive search (n = 12)");

    const des_keyspace_t space = { 12, UINT64_C(0x2A5C3) };
    const uint64_t size   = des_keyspace_size(&space);
    const uint64_t target = 2718;

    const uint64_t secret_key = des_keyspace_key(&space, target);
    const uint64_t ciphertext = des_encrypt_block(KNOWN_PLAINTEXT, secret_key);

    const des_attack_result_t result =
        des_brute_force(&space, KNOWN_PLAINTEXT, ciphertext, 0, size);

    expect_true("the search recovers the planted key", result.found);
    expect_u64("it reports the right candidate", result.candidate, target);
    expect_u64("it reports the right 64-bit key", result.key, secret_key);
    expect_u64("it stops at the match instead of sweeping the rest",
               result.candidates_tested, target + 1);
    expect_true("the recovered key reproduces the known ciphertext",
                des_encrypt_block(KNOWN_PLAINTEXT, result.key) == ciphertext);

    const des_attack_result_t missing =
        des_brute_force(&space, KNOWN_PLAINTEXT, ciphertext, 0, 100);

    expect_true("a range that excludes the key reports no match", !missing.found);
    expect_u64("and tests every candidate in that range",
               missing.candidates_tested, UINT64_C(100));

    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Parallel search                                                     */
/* ------------------------------------------------------------------ */

static void test_parallel_search(void)
{
    puts("Parallel exhaustive search");

    const des_keyspace_t space = { 12, UINT64_C(0x2A5C3) };
    const uint64_t size   = des_keyspace_size(&space);
    const uint64_t target = 3141;

    const uint64_t secret_key = des_keyspace_key(&space, target);
    const uint64_t ciphertext = des_encrypt_block(KNOWN_PLAINTEXT, secret_key);

    static const unsigned worker_counts[] = { 1, 2, 4, 8 };
    int all_found = 1;

    for (unsigned i = 0; i < sizeof worker_counts / sizeof worker_counts[0]; ++i) {
        const des_attack_result_t result =
            des_brute_force_parallel(&space, KNOWN_PLAINTEXT, ciphertext, 0, size,
                                     worker_counts[i]);

        if (!result.found || result.candidate != target || result.key != secret_key) {
            all_found = 0;
        }
    }
    expect_true("1, 2, 4, and 8 workers all recover the same key", all_found);

    const des_attack_result_t zero_workers =
        des_brute_force_parallel(&space, KNOWN_PLAINTEXT, ciphertext, 0, size, 0);
    expect_true("0 workers falls back to a sequential search",
                zero_workers.found && zero_workers.candidate == target);

    const des_attack_result_t missing =
        des_brute_force_parallel(&space, KNOWN_PLAINTEXT, ciphertext, 0, 100, 4);
    expect_true("a range that excludes the key reports no match", !missing.found);

    /* With the key in the first interval, the other workers should notice
     * the stop flag well before finishing their own. */
    const des_keyspace_t wide = { 16, UINT64_C(0x2A5C) };
    const uint64_t wide_size = des_keyspace_size(&wide);
    const uint64_t early_key = des_keyspace_key(&wide, 0);
    const uint64_t early_cipher = des_encrypt_block(KNOWN_PLAINTEXT, early_key);

    const des_attack_result_t early =
        des_brute_force_parallel(&wide, KNOWN_PLAINTEXT, early_cipher, 0, wide_size, 4);

    expect_true("an early match is still found with 4 workers",
                early.found && early.candidate == 0);
    expect_true("and the other workers stop before sweeping the whole space",
                early.candidates_tested < wide_size);

    putchar('\n');
}

/* ------------------------------------------------------------------ */

int main(void)
{
    puts("== Brute-force test suite ==\n");

    test_keyspace();
    test_sequential_search();
    test_parallel_search();

    printf("Result: %u/%u checks passed\n",
           g_checks_run - g_checks_failed, g_checks_run);

    if (g_checks_failed != 0) {
        printf("%u checks FAILED\n", g_checks_failed);
        return EXIT_FAILURE;
    }

    puts("All checks passed.");
    return EXIT_SUCCESS;
}
