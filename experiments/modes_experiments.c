/*
 * Part I experiments for the lab report: the repeated-block contrast between
 * ECB and CBC, the effect of the IV, and error propagation after a single
 * flipped ciphertext bit.
 *
 * Prints block-level hex so the numbers in the report can be traced back to
 * a run of this program.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "des_api.h"
#include "des_modes.h"

#define BUFFER_BYTES 64

static const uint8_t k_key[DES_KEY_BYTES] = {
    0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1
};
static const uint8_t k_iv[DES_IV_BYTES] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};
static const uint8_t k_iv_other[DES_IV_BYTES] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02
};

/* Four identical 8-byte blocks. */
static const char *const k_repeated = "ABCDEFGHABCDEFGHABCDEFGHABCDEFGH";

static void print_blocks(const char *label, const uint8_t *data, size_t length)
{
    for (size_t offset = 0; offset < length; offset += DES_BLOCK_BYTES) {
        printf("  %s block %zu  ", label, offset / DES_BLOCK_BYTES + 1);

        for (size_t i = 0; i < DES_BLOCK_BYTES; ++i) {
            printf("%02X", data[offset + i]);
        }

        putchar('\n');
    }
}

static unsigned popcount8(uint8_t value)
{
    unsigned count = 0;

    while (value != 0) {
        count += (unsigned)(value & 1u);
        value = (uint8_t)(value >> 1);
    }

    return count;
}

static unsigned block_bit_differences(const uint8_t *a, const uint8_t *b)
{
    unsigned total = 0;

    for (size_t i = 0; i < DES_BLOCK_BYTES; ++i) {
        total += popcount8((uint8_t)(a[i] ^ b[i]));
    }

    return total;
}

static unsigned count_repeated_blocks(const uint8_t *data, size_t length)
{
    unsigned repeats = 0;

    for (size_t i = DES_BLOCK_BYTES; i < length; i += DES_BLOCK_BYTES) {
        if (memcmp(data, &data[i], DES_BLOCK_BYTES) == 0) {
            ++repeats;
        }
    }

    return repeats;
}

static void experiment_repeated_blocks(void)
{
    puts("== Experiment 1: identical plaintext blocks under ECB and CBC ==\n");

    const size_t length = strlen(k_repeated);
    uint8_t ecb[BUFFER_BYTES];
    uint8_t cbc[BUFFER_BYTES];
    size_t ecb_len = 0;
    size_t cbc_len = 0;

    if (des_ecb_encrypt(k_key, DES_KEY_BYTES, (const uint8_t *)k_repeated, length,
                        ecb, sizeof ecb, &ecb_len) != DES_OK
        || des_cbc_encrypt(k_key, DES_KEY_BYTES, k_iv, DES_IV_BYTES,
                           (const uint8_t *)k_repeated, length,
                           cbc, sizeof cbc, &cbc_len) != DES_OK) {
        puts("  encryption failed");
        return;
    }

    printf("Plaintext (%zu bytes): \"%s\"\n", length, k_repeated);
    print_blocks("plaintext ", (const uint8_t *)k_repeated, length);
    putchar('\n');

    print_blocks("ECB cipher", ecb, ecb_len);
    printf("  ECB blocks equal to block 1: %u of %zu\n\n",
           count_repeated_blocks(ecb, length), length / DES_BLOCK_BYTES - 1);

    print_blocks("CBC cipher", cbc, cbc_len);
    printf("  CBC blocks equal to block 1: %u of %zu\n\n",
           count_repeated_blocks(cbc, length), length / DES_BLOCK_BYTES - 1);
}

static void experiment_iv_effect(void)
{
    puts("== Experiment 2: same key and plaintext, two different IVs ==\n");

    const size_t length = strlen(k_repeated);
    uint8_t first[BUFFER_BYTES];
    uint8_t second[BUFFER_BYTES];
    size_t first_len = 0;
    size_t second_len = 0;

    if (des_cbc_encrypt(k_key, DES_KEY_BYTES, k_iv, DES_IV_BYTES,
                        (const uint8_t *)k_repeated, length,
                        first, sizeof first, &first_len) != DES_OK
        || des_cbc_encrypt(k_key, DES_KEY_BYTES, k_iv_other, DES_IV_BYTES,
                           (const uint8_t *)k_repeated, length,
                           second, sizeof second, &second_len) != DES_OK) {
        puts("  encryption failed");
        return;
    }

    print_blocks("IV1 cipher", first, first_len);
    putchar('\n');
    print_blocks("IV2 cipher", second, second_len);

    unsigned differing_blocks = 0;
    unsigned differing_bits = 0;

    for (size_t offset = 0; offset < first_len; offset += DES_BLOCK_BYTES) {
        const unsigned bits = block_bit_differences(&first[offset], &second[offset]);

        differing_bits += bits;
        if (bits != 0) {
            ++differing_blocks;
        }
    }

    printf("\n  ciphertexts identical: %s\n",
           (memcmp(first, second, first_len) == 0) ? "yes" : "no");
    printf("  blocks that differ: %u of %zu\n",
           differing_blocks, first_len / DES_BLOCK_BYTES);
    printf("  total bits that differ: %u of %zu\n\n",
           differing_bits, first_len * 8);
}

/* Flips one bit of the ciphertext, decrypts, and reports the damage per
 * plaintext block. The bit is chosen inside block 2 so the final block,
 * which carries the padding, stays intact and the padding check still
 * passes; corrupting it would abort the decryption instead of showing how
 * the error spreads. */
static void experiment_error_propagation(void)
{
    puts("== Experiment 3: one flipped ciphertext bit ==\n");

    const size_t length = strlen(k_repeated);
    const size_t flip_byte = DES_BLOCK_BYTES + 3; /* block 2, byte 4 */
    const uint8_t flip_mask = 0x08u;              /* bit 4 of that byte */

    uint8_t ecb[BUFFER_BYTES];
    uint8_t cbc[BUFFER_BYTES];
    size_t ecb_len = 0;
    size_t cbc_len = 0;

    if (des_ecb_encrypt(k_key, DES_KEY_BYTES, (const uint8_t *)k_repeated, length,
                        ecb, sizeof ecb, &ecb_len) != DES_OK
        || des_cbc_encrypt(k_key, DES_KEY_BYTES, k_iv, DES_IV_BYTES,
                           (const uint8_t *)k_repeated, length,
                           cbc, sizeof cbc, &cbc_len) != DES_OK) {
        puts("  encryption failed");
        return;
    }

    printf("Flipped bit: ciphertext block 2, byte %zu of the message, mask %02X\n\n",
           flip_byte + 1, flip_mask);

    ecb[flip_byte] ^= flip_mask;
    cbc[flip_byte] ^= flip_mask;

    uint8_t ecb_plain[BUFFER_BYTES];
    uint8_t cbc_plain[BUFFER_BYTES];
    size_t ecb_plain_len = 0;
    size_t cbc_plain_len = 0;

    const des_status_t ecb_status = des_ecb_decrypt(k_key, DES_KEY_BYTES, ecb, ecb_len,
                                                    ecb_plain, sizeof ecb_plain,
                                                    &ecb_plain_len);
    const des_status_t cbc_status = des_cbc_decrypt(k_key, DES_KEY_BYTES, k_iv, DES_IV_BYTES,
                                                    cbc, cbc_len, cbc_plain,
                                                    sizeof cbc_plain, &cbc_plain_len);

    printf("  ECB decrypt status: %d, CBC decrypt status: %d  (0 = DES_OK)\n\n",
           (int)ecb_status, (int)cbc_status);

    const uint8_t *original = (const uint8_t *)k_repeated;
    const size_t blocks = length / DES_BLOCK_BYTES;

    puts("  Block   ECB bits changed   CBC bits changed");

    unsigned ecb_blocks = 0;
    unsigned cbc_blocks = 0;
    unsigned ecb_bits = 0;
    unsigned cbc_bits = 0;

    for (size_t i = 0; i < blocks; ++i) {
        const size_t offset = i * DES_BLOCK_BYTES;
        const unsigned in_ecb = (ecb_status == DES_OK)
                              ? block_bit_differences(&original[offset], &ecb_plain[offset])
                              : 0;
        const unsigned in_cbc = (cbc_status == DES_OK)
                              ? block_bit_differences(&original[offset], &cbc_plain[offset])
                              : 0;

        printf("  %5zu   %16u   %16u\n", i + 1, in_ecb, in_cbc);

        ecb_bits += in_ecb;
        cbc_bits += in_cbc;
        if (in_ecb != 0) { ++ecb_blocks; }
        if (in_cbc != 0) { ++cbc_blocks; }
    }

    printf("\n  ECB: %u of %zu plaintext blocks damaged, %u bits total\n",
           ecb_blocks, blocks, ecb_bits);
    printf("  CBC: %u of %zu plaintext blocks damaged, %u bits total\n",
           cbc_blocks, blocks, cbc_bits);
}

int main(void)
{
    puts("== DES modes of operation: Part I experiments ==\n");

    printf("Key: ");
    for (size_t i = 0; i < DES_KEY_BYTES; ++i) { printf("%02X", k_key[i]); }
    printf("   IV1: ");
    for (size_t i = 0; i < DES_IV_BYTES; ++i) { printf("%02X", k_iv[i]); }
    printf("   IV2: ");
    for (size_t i = 0; i < DES_IV_BYTES; ++i) { printf("%02X", k_iv_other[i]); }
    puts("\n");

    experiment_repeated_blocks();
    experiment_iv_effect();
    experiment_error_propagation();

    return 0;
}
