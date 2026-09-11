/*
 * Test suite for the DES library.
 *
 * Covers every case required by the lab spec: the known FIPS 46-3 vector,
 * the k1/k16 round keys, a round-trip check, the avalanche effect (one
 * plaintext bit and one key bit), rejection of wrong-length input, and a
 * dedicated check that the bit-numbering convention (bit 1 = MSB) is
 * actually being used. The modes layer adds PKCS#7 padding round trips and
 * invalid padding, ECB and CBC round trips, the IV's effect, and the
 * repeated-block contrast between the two modes.
 * No external test framework -- just a tiny counter.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "des.h"
#include "des_api.h"
#include "des_feistel.h"
#include "des_keyschedule.h"
#include "des_modes.h"
#include "des_tables.h"

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
        printf("         expected: %016" PRIX64 "\n", expected);
        printf("         actual:   %016" PRIX64 "\n", actual);
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

/* Same permute() used across the library -- reimplemented here so the
 * tables can be checked without trusting the code under test. */
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

/* ------------------------------------------------------------------ */
/* Table sanity checks                                                 */
/* ------------------------------------------------------------------ */

static int table_is_bijection(const uint8_t *table, unsigned length)
{
    unsigned char seen[DES_BLOCK_BITS + 1] = { 0 };

    for (unsigned i = 0; i < length; ++i) {
        if (table[i] < 1 || table[i] > length || seen[table[i]] != 0) {
            return 0;
        }
        seen[table[i]] = 1;
    }

    return 1;
}

static void test_tables(void)
{
    puts("Tables");

    expect_true("IP is a bijection over 64 bits",
                table_is_bijection(DES_IP, DES_BLOCK_BITS));
    expect_true("IP_INV is a bijection over 64 bits",
                table_is_bijection(DES_IP_INV, DES_BLOCK_BITS));
    expect_true("P is a bijection over 32 bits",
                table_is_bijection(DES_P, DES_HALF_BLOCK_BITS));

    const uint64_t sample = UINT64_C(0x0123456789ABCDEF);
    const uint64_t round_trip = permute(permute(sample, DES_IP, DES_BLOCK_BITS, DES_BLOCK_BITS),
                                        DES_IP_INV, DES_BLOCK_BITS, DES_BLOCK_BITS);
    expect_u64("IP_INV(IP(x)) == x", round_trip, sample);

    unsigned shift_total = 0;
    for (unsigned i = 0; i < DES_ROUNDS; ++i) {
        shift_total += DES_SHIFTS[i];
    }
    expect_true("the 16 shifts sum to 28 (C, D cycle back to their start)",
                shift_total == DES_KEY_HALF_BITS);

    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Bit order: bit 1 of the spec must be the MSB, not the LSB           */
/* ------------------------------------------------------------------ */

static void test_bit_order(void)
{
    puts("Bit order (fails if bit 1 were read as the LSB)");

    /* Only spec bit 1 set -- the block's most significant bit. */
    const uint64_t only_bit_one = UINT64_C(1) << 63;

    /* DES_IP[39] == 1, so spec bit 1 lands at output position 40. Under
     * our MSB-first convention that's shift (64 - 40) = 24. Reading bit 1
     * as the LSB instead would shift this to a completely different bit,
     * so this check pins down the convention directly. */
    const uint64_t permuted = permute(only_bit_one, DES_IP, DES_BLOCK_BITS, DES_BLOCK_BITS);
    const uint64_t expected = UINT64_C(1) << 24;

    expect_u64("IP sends spec bit 1 to output position 40", permuted, expected);

    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* S-box: the lab's own worked example                                 */
/* ------------------------------------------------------------------ */

static void test_sbox_explicit(void)
{
    puts("S-box (lab's worked example: S1(100101b) = 1000b)");

    const uint8_t six_bits = 0x25; /* binary 100101 */

    /* Same row/col split used inside des_feistel.c's substitute(). */
    const unsigned row = (unsigned)(((six_bits & 0x20u) >> 4) | (six_bits & 0x01u));
    const unsigned col = (unsigned)((six_bits >> 1) & 0x0Fu);

    expect_true("row == 3 (outer bits '1' and '1')", row == 3);
    expect_true("col == 2 (middle bits '0010')", col == 2);
    expect_true("S1(100101b) == 1000b (decimal 8)", DES_SBOX[0][row][col] == 8);

    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Feistel function and one round, tested on their own                 */
/* ------------------------------------------------------------------ */

static void test_round_and_feistel(void)
{
    puts("Feistel function and one round (independent unit checks)");

    const uint32_t half   = 0x12345678u;
    const uint64_t subkey = UINT64_C(0x1B02EFFC7072); /* k1 for the FIPS sample key */

    expect_u64("des_feistel_f is deterministic (same input, same output)",
               des_feistel_f(half, subkey), des_feistel_f(half, subkey));

    const uint32_t left  = 0xAABBCCDDu;
    const uint32_t right = 0x11223344u;
    const des_half_pair_t next = des_round(left, right, subkey);

    expect_true("des_round: new left == old right", next.left == right);
    expect_u64("des_round: new right == left XOR f(right, key)",
               next.right, left ^ des_feistel_f(right, subkey));

    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Key schedule: k1 and k16 from the FIPS 46-3 example                 */
/* ------------------------------------------------------------------ */

static void test_key_schedule(void)
{
    puts("Key schedule (key 133457799BBCDFF1)");

    uint64_t round_keys[DES_ROUNDS];
    des_generate_round_keys(UINT64_C(0x133457799BBCDFF1), round_keys);

    expect_u64("k1  == 1B02EFFC7072", round_keys[0], UINT64_C(0x1B02EFFC7072));
    expect_u64("k16 == CB3D8B0E17F5", round_keys[15], UINT64_C(0xCB3D8B0E17F5));

    int within_48_bits = 1;
    for (unsigned i = 0; i < DES_ROUNDS; ++i) {
        if (round_keys[i] >> DES_SUBKEY_BITS) {
            within_48_bits = 0;
        }
    }
    expect_true("every subkey fits in 48 bits", within_48_bits);

    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Known vector (core uint64_t primitive)                              */
/* ------------------------------------------------------------------ */

static void test_known_vector(void)
{
    puts("Known vector (FIPS 46-3)");

    const uint64_t key   = UINT64_C(0x133457799BBCDFF1);
    const uint64_t plain = UINT64_C(0x0123456789ABCDEF);
    const uint64_t expected_cipher = UINT64_C(0x85E813540F0AB405);

    expect_u64("des_encrypt_block(P, K) == C",
               des_encrypt_block(plain, key), expected_cipher);
    expect_u64("des_decrypt_block(C, K) == P",
               des_decrypt_block(expected_cipher, key), plain);

    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Byte-oriented API (des_encrypt / des_decrypt / des_check_parity)    */
/* ------------------------------------------------------------------ */

static void test_byte_api(void)
{
    puts("Byte-oriented API");

    const uint8_t key[DES_KEY_BYTES] = {
        0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1
    };
    const uint8_t plain[DES_BLOCK_BYTES] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    const uint8_t expected_cipher[DES_BLOCK_BYTES] = {
        0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05
    };

    uint8_t cipher[DES_BLOCK_BYTES];
    uint8_t recovered[DES_BLOCK_BYTES];

    expect_true("des_encrypt succeeds on valid-length input",
                des_encrypt(key, DES_KEY_BYTES, plain, DES_BLOCK_BYTES, cipher) == DES_OK);
    expect_true("des_encrypt matches the known vector",
                memcmp(cipher, expected_cipher, DES_BLOCK_BYTES) == 0);

    expect_true("des_decrypt succeeds on valid-length input",
                des_decrypt(key, DES_KEY_BYTES, cipher, DES_BLOCK_BYTES, recovered) == DES_OK);
    expect_true("des_decrypt recovers the original plaintext",
                memcmp(recovered, plain, DES_BLOCK_BYTES) == 0);

    bool parity_ok = false;
    expect_true("des_check_parity succeeds on valid-length input",
                des_check_parity(key, DES_KEY_BYTES, &parity_ok) == DES_OK);
    expect_true("the FIPS sample key has correct odd parity", parity_ok);

    uint8_t bad_parity_key[DES_KEY_BYTES];
    memcpy(bad_parity_key, key, DES_KEY_BYTES);
    bad_parity_key[0] ^= 0x01u; /* flip byte 0's parity bit (its LSB) */

    expect_true("des_check_parity still succeeds (length is still valid)",
                des_check_parity(bad_parity_key, DES_KEY_BYTES, &parity_ok) == DES_OK);
    expect_true("a flipped parity bit is reported as invalid", !parity_ok);

    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Invalid input: wrong-length keys and blocks must be rejected        */
/* ------------------------------------------------------------------ */

static void test_invalid_input(void)
{
    puts("Invalid input (7-byte and 9-byte keys/blocks)");

    const uint8_t key[DES_KEY_BYTES] = {
        0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1
    };
    const uint8_t block[DES_BLOCK_BYTES] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    uint8_t out[DES_BLOCK_BYTES];
    uint64_t round_keys[DES_ROUNDS];
    bool parity_ok = false;

    expect_true("des_encrypt rejects a 7-byte key",
                des_encrypt(key, 7, block, DES_BLOCK_BYTES, out) == DES_ERR_INVALID_LENGTH);
    expect_true("des_encrypt rejects a 9-byte key",
                des_encrypt(key, 9, block, DES_BLOCK_BYTES, out) == DES_ERR_INVALID_LENGTH);
    expect_true("des_encrypt rejects a 7-byte block",
                des_encrypt(key, DES_KEY_BYTES, block, 7, out) == DES_ERR_INVALID_LENGTH);
    expect_true("des_encrypt rejects a 9-byte block",
                des_encrypt(key, DES_KEY_BYTES, block, 9, out) == DES_ERR_INVALID_LENGTH);

    expect_true("des_decrypt rejects a 7-byte key",
                des_decrypt(key, 7, block, DES_BLOCK_BYTES, out) == DES_ERR_INVALID_LENGTH);
    expect_true("des_decrypt rejects a 9-byte block",
                des_decrypt(key, DES_KEY_BYTES, block, 9, out) == DES_ERR_INVALID_LENGTH);

    expect_true("des_key_schedule rejects a 7-byte key",
                des_key_schedule(key, 7, round_keys) == DES_ERR_INVALID_LENGTH);
    expect_true("des_check_parity rejects a 9-byte key",
                des_check_parity(key, 9, &parity_ok) == DES_ERR_INVALID_LENGTH);

    expect_true("a correctly sized call still succeeds",
                des_encrypt(key, DES_KEY_BYTES, block, DES_BLOCK_BYTES, out) == DES_OK);

    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Round trip and avalanche effect                                     */
/* ------------------------------------------------------------------ */

/* Linear congruential generator: not cryptographically random, and it
 * doesn't need to be -- this just needs a deterministic, reproducible
 * sweep of the input space, not real entropy. */
static uint64_t lcg_next(uint64_t *state)
{
    *state = (*state * UINT64_C(6364136223846793005)) + UINT64_C(1442695040888963407);
    return *state;
}

static void test_round_trip(void)
{
    puts("Round trip (lab requires at least 20 blocks; this runs 1000)");

    uint64_t state = UINT64_C(0x123456789ABCDEF0);
    int ok = 1;

    for (unsigned i = 0; i < 1000; ++i) {
        const uint64_t block = lcg_next(&state);
        const uint64_t key   = lcg_next(&state);

        if (des_decrypt_block(des_encrypt_block(block, key), key) != block) {
            ok = 0;
            break;
        }
    }

    expect_true("decrypt(encrypt(x)) == x for every test block", ok);

    putchar('\n');
}

static unsigned popcount64(uint64_t value)
{
    unsigned count = 0;
    while (value != 0) {
        count += (unsigned)(value & UINT64_C(1));
        value >>= 1;
    }
    return count;
}

static void test_avalanche_plaintext(void)
{
    puts("Avalanche effect (one plaintext bit flipped)");

    const uint64_t key = UINT64_C(0x133457799BBCDFF1);
    const uint64_t base = UINT64_C(0x0123456789ABCDEF);
    const uint64_t base_cipher = des_encrypt_block(base, key);

    unsigned min_diff = DES_BLOCK_BITS;
    unsigned max_diff = 0;

    for (unsigned bit = 0; bit < DES_BLOCK_BITS; ++bit) {
        const uint64_t altered = des_encrypt_block(base ^ (UINT64_C(1) << bit), key);
        const unsigned diff = popcount64(base_cipher ^ altered);

        if (diff < min_diff) { min_diff = diff; }
        if (diff > max_diff) { max_diff = diff; }
    }

    printf("         changed ciphertext bits: min=%u, max=%u (ideal ~32)\n",
           min_diff, max_diff);
    expect_true("within the lab's 20-44 bit range", min_diff >= 20 && max_diff <= 44);

    putchar('\n');
}

static void test_avalanche_key(void)
{
    puts("Avalanche effect (one effective key bit flipped, no parity bits)");

    const uint64_t key = UINT64_C(0x133457799BBCDFF1);
    const uint64_t plain = UINT64_C(0x0123456789ABCDEF);
    const uint64_t base_cipher = des_encrypt_block(plain, key);

    unsigned min_diff = DES_BLOCK_BITS;
    unsigned max_diff = 0;

    for (unsigned shift = 0; shift < DES_BLOCK_BITS; ++shift) {
        if (shift % 8 == 0) {
            continue; /* parity bits sit at shifts 0, 8, 16, ..., 56 */
        }

        const uint64_t altered = des_encrypt_block(plain, key ^ (UINT64_C(1) << shift));
        const unsigned diff = popcount64(base_cipher ^ altered);

        if (diff < min_diff) { min_diff = diff; }
        if (diff > max_diff) { max_diff = diff; }
    }

    printf("         changed ciphertext bits: min=%u, max=%u (ideal ~32)\n",
           min_diff, max_diff);
    expect_true("within the lab's 20-44 bit range", min_diff >= 20 && max_diff <= 44);

    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Modes layer: PKCS#7 padding, ECB, CBC                               */
/* ------------------------------------------------------------------ */

/* Empty, short, exactly one block, and several blocks. */
static const char *const k_messages[] = {
    "", "A", "1234567", "12345678", "123456789", "Hola, DES desde C!"
};

#define MESSAGE_COUNT (sizeof k_messages / sizeof k_messages[0])

static const uint8_t k_key[DES_KEY_BYTES] = {
    0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1
};
static const uint8_t k_iv[DES_IV_BYTES] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};
static const uint8_t k_fips_plain[DES_BLOCK_BYTES] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
};
static const uint8_t k_fips_cipher[DES_BLOCK_BYTES] = {
    0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05
};

static void test_padding(void)
{
    puts("PKCS#7 padding");

    int lengths_ok = 1;
    int round_trip_ok = 1;

    for (size_t i = 0; i < MESSAGE_COUNT; ++i) {
        const uint8_t *data  = (const uint8_t *)k_messages[i];
        const size_t data_len = strlen(k_messages[i]);

        uint8_t padded[64];
        size_t padded_len = 0;
        size_t unpadded_len = 0;

        if (des_pkcs7_pad(data, data_len, padded, sizeof padded, &padded_len) != DES_OK
            || padded_len != des_padded_len(data_len)
            || padded_len <= data_len
            || (padded_len % DES_BLOCK_BYTES) != 0) {
            lengths_ok = 0;
            break;
        }

        if (des_pkcs7_unpad(padded, padded_len, &unpadded_len) != DES_OK
            || unpadded_len != data_len
            || memcmp(padded, data, data_len) != 0) {
            round_trip_ok = 0;
            break;
        }
    }

    expect_true("pad fills whole blocks and always adds at least one byte", lengths_ok);
    expect_true("unpad(pad(M)) == M for messages of several lengths", round_trip_ok);

    uint8_t aligned[2 * DES_BLOCK_BYTES];
    size_t aligned_len = 0;
    expect_true("a block-aligned message gains a full padding block",
                des_pkcs7_pad((const uint8_t *)"12345678", DES_BLOCK_BYTES,
                              aligned, sizeof aligned, &aligned_len) == DES_OK
                && aligned_len == 2 * DES_BLOCK_BYTES
                && aligned[8] == 8 && aligned[15] == 8);

    uint8_t bad[DES_BLOCK_BYTES];
    size_t out_len = 0;

    memset(bad, 8, sizeof bad);
    bad[DES_BLOCK_BYTES - 1] = 0;
    expect_true("unpad rejects a zero pad byte",
                des_pkcs7_unpad(bad, sizeof bad, &out_len) == DES_ERR_INVALID_PADDING);

    memset(bad, 9, sizeof bad);
    expect_true("unpad rejects a pad byte above the block size",
                des_pkcs7_unpad(bad, sizeof bad, &out_len) == DES_ERR_INVALID_PADDING);

    memset(bad, 0, sizeof bad);
    bad[DES_BLOCK_BYTES - 1] = 3;
    bad[DES_BLOCK_BYTES - 2] = 3; /* the run claims 3 bytes but the third is 0 */
    expect_true("unpad rejects an inconsistent padding run",
                des_pkcs7_unpad(bad, sizeof bad, &out_len) == DES_ERR_INVALID_PADDING);

    expect_true("unpad rejects a length that isn't a multiple of 8",
                des_pkcs7_unpad(bad, 7, &out_len) == DES_ERR_INVALID_LENGTH);
    expect_true("unpad rejects an empty buffer",
                des_pkcs7_unpad(bad, 0, &out_len) == DES_ERR_INVALID_LENGTH);

    uint8_t tiny[4];
    expect_true("pad rejects an output buffer that is too small",
                des_pkcs7_pad((const uint8_t *)"AB", 2, tiny, sizeof tiny, &out_len)
                    == DES_ERR_BUFFER_TOO_SMALL);

    putchar('\n');
}

static void test_ecb(void)
{
    puts("ECB mode");

    uint8_t cipher[64];
    uint8_t recovered[64];
    size_t cipher_len = 0;
    size_t recovered_len = 0;

    expect_true("des_ecb_encrypt succeeds on valid input",
                des_ecb_encrypt(k_key, DES_KEY_BYTES, k_fips_plain, DES_BLOCK_BYTES,
                                cipher, sizeof cipher, &cipher_len) == DES_OK);
    expect_true("a block-aligned plaintext yields one extra ciphertext block",
                cipher_len == 2 * DES_BLOCK_BYTES);
    expect_true("the first ECB block matches the known FIPS vector",
                memcmp(cipher, k_fips_cipher, DES_BLOCK_BYTES) == 0);

    expect_true("des_ecb_decrypt succeeds on valid input",
                des_ecb_decrypt(k_key, DES_KEY_BYTES, cipher, cipher_len,
                                recovered, sizeof recovered, &recovered_len) == DES_OK);
    expect_true("ECB decrypt strips the padding and recovers the plaintext",
                recovered_len == DES_BLOCK_BYTES
                && memcmp(recovered, k_fips_plain, DES_BLOCK_BYTES) == 0);

    int round_trip_ok = 1;
    for (size_t i = 0; i < MESSAGE_COUNT; ++i) {
        const uint8_t *data  = (const uint8_t *)k_messages[i];
        const size_t data_len = strlen(k_messages[i]);

        if (des_ecb_encrypt(k_key, DES_KEY_BYTES, data, data_len,
                            cipher, sizeof cipher, &cipher_len) != DES_OK
            || des_ecb_decrypt(k_key, DES_KEY_BYTES, cipher, cipher_len,
                               recovered, sizeof recovered, &recovered_len) != DES_OK
            || recovered_len != data_len
            || memcmp(recovered, data, data_len) != 0) {
            round_trip_ok = 0;
            break;
        }
    }
    expect_true("D_ECB(E_ECB(M)) == M for messages of several lengths", round_trip_ok);

    expect_true("des_ecb_encrypt rejects a 7-byte key",
                des_ecb_encrypt(k_key, 7, k_fips_plain, DES_BLOCK_BYTES,
                                cipher, sizeof cipher, &cipher_len) == DES_ERR_INVALID_LENGTH);
    expect_true("des_ecb_decrypt rejects a ciphertext that isn't a multiple of 8",
                des_ecb_decrypt(k_key, DES_KEY_BYTES, cipher, 15,
                                recovered, sizeof recovered, &recovered_len)
                    == DES_ERR_INVALID_LENGTH);

    uint8_t tiny[DES_BLOCK_BYTES];
    expect_true("des_ecb_encrypt rejects an output buffer that is too small",
                des_ecb_encrypt(k_key, DES_KEY_BYTES, k_fips_plain, DES_BLOCK_BYTES,
                                tiny, sizeof tiny, &cipher_len) == DES_ERR_BUFFER_TOO_SMALL);

    putchar('\n');
}

static void test_cbc(void)
{
    puts("CBC mode");

    uint8_t cipher[64];
    uint8_t recovered[64];
    size_t cipher_len = 0;
    size_t recovered_len = 0;

    /* P_1 XOR IV is the FIPS plaintext, so C_1 must be the FIPS ciphertext.
     * An all-zero IV would pass even if the XOR were missing; this won't. */
    uint8_t first_block[DES_BLOCK_BYTES];
    for (size_t i = 0; i < DES_BLOCK_BYTES; ++i) {
        first_block[i] = (uint8_t)(k_fips_plain[i] ^ k_iv[i]);
    }

    expect_true("des_cbc_encrypt succeeds on valid input",
                des_cbc_encrypt(k_key, DES_KEY_BYTES, k_iv, DES_IV_BYTES,
                                first_block, DES_BLOCK_BYTES,
                                cipher, sizeof cipher, &cipher_len) == DES_OK);
    expect_true("C_1 == E_K(P_1 XOR IV), checked against the FIPS vector",
                memcmp(cipher, k_fips_cipher, DES_BLOCK_BYTES) == 0);

    int round_trip_ok = 1;
    for (size_t i = 0; i < MESSAGE_COUNT; ++i) {
        const uint8_t *data  = (const uint8_t *)k_messages[i];
        const size_t data_len = strlen(k_messages[i]);

        if (des_cbc_encrypt(k_key, DES_KEY_BYTES, k_iv, DES_IV_BYTES, data, data_len,
                            cipher, sizeof cipher, &cipher_len) != DES_OK
            || des_cbc_decrypt(k_key, DES_KEY_BYTES, k_iv, DES_IV_BYTES, cipher, cipher_len,
                               recovered, sizeof recovered, &recovered_len) != DES_OK
            || recovered_len != data_len
            || memcmp(recovered, data, data_len) != 0) {
            round_trip_ok = 0;
            break;
        }
    }
    expect_true("D_CBC(E_CBC(M, IV), IV) == M for messages of several lengths", round_trip_ok);

    const uint8_t other_iv[DES_IV_BYTES] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02
    };
    const uint8_t *message  = (const uint8_t *)k_messages[MESSAGE_COUNT - 1];
    const size_t message_len = strlen(k_messages[MESSAGE_COUNT - 1]);

    uint8_t cipher_a[64];
    uint8_t cipher_b[64];
    size_t len_a = 0;
    size_t len_b = 0;

    expect_true("the same message encrypts under both IVs",
                des_cbc_encrypt(k_key, DES_KEY_BYTES, k_iv, DES_IV_BYTES, message, message_len,
                                cipher_a, sizeof cipher_a, &len_a) == DES_OK
                && des_cbc_encrypt(k_key, DES_KEY_BYTES, other_iv, DES_IV_BYTES,
                                   message, message_len,
                                   cipher_b, sizeof cipher_b, &len_b) == DES_OK);
    expect_true("two different IVs produce different ciphertexts",
                len_a == len_b && memcmp(cipher_a, cipher_b, len_a) != 0);

    expect_true("CBC decrypt with the matching IV recovers the plaintext",
                des_cbc_decrypt(k_key, DES_KEY_BYTES, k_iv, DES_IV_BYTES, cipher_a, len_a,
                                recovered, sizeof recovered, &recovered_len) == DES_OK
                && recovered_len == message_len
                && memcmp(recovered, message, message_len) == 0);

    expect_true("des_cbc_encrypt rejects a 7-byte IV",
                des_cbc_encrypt(k_key, DES_KEY_BYTES, k_iv, 7, message, message_len,
                                cipher, sizeof cipher, &cipher_len) == DES_ERR_INVALID_LENGTH);
    expect_true("des_cbc_decrypt rejects a 9-byte IV",
                des_cbc_decrypt(k_key, DES_KEY_BYTES, k_iv, 9, cipher_a, len_a,
                                recovered, sizeof recovered, &recovered_len)
                    == DES_ERR_INVALID_LENGTH);

    putchar('\n');
}

static void test_repeated_blocks(void)
{
    puts("Repeated plaintext blocks (ECB leaks them, CBC does not)");

    const char *const repeated = "ABCDEFGHABCDEFGHABCDEFGHABCDEFGH"; /* 4 identical blocks */
    const size_t repeated_len  = strlen(repeated);

    uint8_t ecb[64];
    uint8_t cbc[64];
    size_t ecb_len = 0;
    size_t cbc_len = 0;

    expect_true("both modes encrypt the repeated message",
                des_ecb_encrypt(k_key, DES_KEY_BYTES, (const uint8_t *)repeated, repeated_len,
                                ecb, sizeof ecb, &ecb_len) == DES_OK
                && des_cbc_encrypt(k_key, DES_KEY_BYTES, k_iv, DES_IV_BYTES,
                                   (const uint8_t *)repeated, repeated_len,
                                   cbc, sizeof cbc, &cbc_len) == DES_OK);

    int ecb_all_equal = 1;
    int cbc_any_equal = 0;

    for (size_t offset = DES_BLOCK_BYTES; offset < repeated_len; offset += DES_BLOCK_BYTES) {
        if (memcmp(ecb, &ecb[offset], DES_BLOCK_BYTES) != 0) {
            ecb_all_equal = 0;
        }
        if (memcmp(cbc, &cbc[offset], DES_BLOCK_BYTES) == 0) {
            cbc_any_equal = 1;
        }
    }

    expect_true("ECB maps the 4 identical plaintext blocks to identical ciphertext blocks",
                ecb_all_equal);
    expect_true("CBC produces 4 distinct ciphertext blocks instead", !cbc_any_equal);

    putchar('\n');
}

/* ------------------------------------------------------------------ */

int main(void)
{
    puts("== DES test suite ==\n");

    test_tables();
    test_bit_order();
    test_sbox_explicit();
    test_round_and_feistel();
    test_key_schedule();
    test_known_vector();
    test_byte_api();
    test_invalid_input();
    test_round_trip();
    test_avalanche_plaintext();
    test_avalanche_key();
    test_padding();
    test_ecb();
    test_cbc();
    test_repeated_blocks();

    printf("Result: %u/%u checks passed\n",
           g_checks_run - g_checks_failed, g_checks_run);

    if (g_checks_failed != 0) {
        printf("%u checks FAILED\n", g_checks_failed);
        return EXIT_FAILURE;
    }

    puts("All checks passed.");
    return EXIT_SUCCESS;
}
