/* candidate -> 56 effective bits -> 64-bit DES key with odd parity. */

#include "des_keyspace.h"

#include <stdint.h>

#include "des_api.h"
#include "des_tables.h"

#define DES_EFFECTIVE_MASK ((UINT64_C(1) << DES_KEY_BITS_EFFECTIVE) - 1)
#define DES_BYTE_DATA_BITS 7

uint64_t des_keyspace_size(const des_keyspace_t *space)
{
    return UINT64_C(1) << space->unknown_bits;
}

uint64_t des_key_with_parity(uint64_t effective_bits)
{
    uint64_t key = 0;

    effective_bits &= DES_EFFECTIVE_MASK;

    for (unsigned byte = 0; byte < DES_KEY_BYTES; ++byte) {
        const unsigned shift = DES_KEY_BITS_EFFECTIVE - DES_BYTE_DATA_BITS * (byte + 1);
        const uint64_t data  = (effective_bits >> shift) & 0x7Fu;

        unsigned ones = 0;
        for (unsigned bit = 0; bit < DES_BYTE_DATA_BITS; ++bit) {
            ones += (unsigned)((data >> bit) & UINT64_C(1));
        }

        key = (key << 8) | (data << 1) | ((ones % 2u == 0u) ? UINT64_C(1) : UINT64_C(0));
    }

    return key;
}

uint64_t des_keyspace_key(const des_keyspace_t *space, uint64_t candidate)
{
    const uint64_t candidate_mask = (UINT64_C(1) << space->unknown_bits) - 1;
    const uint64_t effective = (space->fixed_prefix << space->unknown_bits)
                             | (candidate & candidate_mask);

    return des_key_with_parity(effective);
}
