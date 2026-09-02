/*
 * Demo: encrypt and decrypt a text string.
 *
 * Usage: des_demo ["some text"]
 *
 * Loops over 8-byte blocks and encrypts each one independently -- that's
 * ECB, fine for a demo, not something to use for real multi-block data.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "des.h"

#define DEMO_KEY UINT64_C(0x133457799BBCDFF1) /* FIPS 46-3 sample key */
#define BLOCK_BYTES 8
#define MAX_TEXT_LEN 1024

static const char *k_default_text = "Hola, DES desde C!";

/*
 * Packs 8 bytes into a uint64_t, most significant byte first:
 *
 *   bytes = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H' }
 *   block = 0x41 42 43 44 45 46 47 48
 */
static uint64_t bytes_to_block(const uint8_t bytes[BLOCK_BYTES])
{
    uint64_t block = 0;

    for (int i = 0; i < BLOCK_BYTES; ++i) {
        block = (block << 8) | bytes[i];
    }

    return block;
}

/* Reverses bytes_to_block. */
static void block_to_bytes(uint64_t block, uint8_t bytes[BLOCK_BYTES])
{
    for (int i = BLOCK_BYTES - 1; i >= 0; --i) {
        bytes[i] = (uint8_t)(block & 0xFFu);
        block >>= 8;
    }
}

int main(int argc, char *argv[])
{
    const char *text = (argc >= 2) ? argv[1] : k_default_text;
    const size_t text_len = strlen(text);

    if (text_len == 0 || text_len >= MAX_TEXT_LEN) {
        fprintf(stderr, "Error: text must be 1-%d characters.\n", MAX_TEXT_LEN - 1);
        return 1;
    }

    /* Round up to a whole number of 8-byte blocks. */
    const size_t block_count = (text_len / BLOCK_BYTES) + 1;

    /* Zero-padded buffers: the last block is rarely full, and padding with
     * '\0' means printf("%s", ...) naturally stops right where the text
     * ends, no manual trimming needed. */
    uint8_t plain_buffer[MAX_TEXT_LEN]     = { 0 };
    uint8_t recovered_buffer[MAX_TEXT_LEN] = { 0 };
    memcpy(plain_buffer, text, text_len);

    printf("== DES demo ==\n\n");
    printf("Original text (%zu bytes): \"%s\"\n", text_len, text);
    printf("Demo key:                  %016" PRIX64 "\n", (uint64_t)DEMO_KEY);
    printf("Blocks to encrypt:         %zu\n\n", block_count);

    for (size_t i = 0; i < block_count; ++i) {
        const uint64_t plain_block  = bytes_to_block(&plain_buffer[i * BLOCK_BYTES]);
        const uint64_t cipher_block = des_encrypt_block(plain_block, DEMO_KEY);
        const uint64_t back_block   = des_decrypt_block(cipher_block, DEMO_KEY);

        printf("  block %zu  plain=%016" PRIX64 "  cipher=%016" PRIX64 "\n",
               i, plain_block, cipher_block);

        block_to_bytes(back_block, &recovered_buffer[i * BLOCK_BYTES]);
    }

    printf("\nRecovered text: \"%s\"\n", recovered_buffer);

    if (memcmp(plain_buffer, recovered_buffer, text_len) != 0) {
        fprintf(stderr, "\nERROR: recovered text does not match the original.\n");
        return 1;
    }

    printf("\nText recovered exactly. DES is broken today (56-bit effective\n"
           "key) -- educational use only.\n");

    return 0;
}
