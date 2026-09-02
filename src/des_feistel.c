/*
 * des_feistel.c - Funcion de ronda f(R, K): E -> XOR -> S-boxes -> P.
 *
 * Este modulo desconoce por completo el key schedule: recibe la subclave ya
 * lista. Tampoco sabe en que ronda esta ni como se combinan las mitades del
 * bloque; eso es responsabilidad de la primitiva en des.c.
 */

#include "des_feistel.h"

#include <stdint.h>

#include "des_tables.h"

/* Mascara de la subclave: descarta cualquier bit por encima del 48 para que
 * una entrada mal formada no contamine el XOR con la expansion. */
#define DES_SUBKEY_MASK ((UINT64_C(1) << DES_SUBKEY_BITS) - 1)

/* Ancho de cada trozo que consume una S-box, y de cada trozo que produce. */
#define DES_SBOX_INPUT_BITS  6
#define DES_SBOX_OUTPUT_BITS 4

/*
 * Aplica una tabla de permutacion del estandar.
 *
 * El estandar numera los bits desde 1 empezando por el MAS significativo, de
 * ahi el desplazamiento (in_bits - table[i]).
 */
static uint64_t permute(uint64_t input, const uint8_t *table, unsigned out_bits, unsigned in_bits)
{
    uint64_t output = 0;

    for (unsigned i = 0; i < out_bits; ++i) {
        const uint64_t bit = (input >> (in_bits - table[i])) & UINT64_C(1);
        output = (output << 1) | bit;
    }

    return output;
}

/*
 * Sustituye los 48 bits de entrada por 32 usando las ocho S-boxes.
 *
 * Cada S-box consume un bloque de 6 bits y devuelve 4. El reparto de esos 6
 * bits no es arbitrario:
 *
 *   - La FILA (0..3) la eligen el bit mas significativo y el menos
 *     significativo del bloque.
 *   - La COLUMNA (0..15) la eligen los 4 bits centrales del bloque.
 */
static uint32_t substitute(uint64_t expanded)
{
    uint32_t output = 0;

    for (unsigned box = 0; box < DES_SBOX_COUNT; ++box) {
        /* Los bloques se recorren de izquierda a derecha: el primero ocupa los
         * bits mas significativos de los 48. */
        const unsigned shift = DES_SUBKEY_BITS - DES_SBOX_INPUT_BITS
                             - (box * DES_SBOX_INPUT_BITS);
        const uint8_t chunk = (uint8_t)((expanded >> shift) & 0x3Fu);

        /* Bit 5 (MSB del bloque) -> bit 1 de la fila; bit 0 (LSB) -> bit 0. */
        const unsigned row = (unsigned)(((chunk & 0x20u) >> 4) | (chunk & 0x01u));
        /* Bits 4..1: los cuatro centrales. */
        const unsigned col = (unsigned)((chunk >> 1) & 0x0Fu);

        output = (output << DES_SBOX_OUTPUT_BITS) | DES_SBOX[box][row][col];
    }

    return output;
}

uint32_t des_feistel_f(uint32_t half_block, uint64_t round_key)
{
    /* 1. Expansion E: 32 -> 48 bits, duplicando los bits de los bordes. */
    const uint64_t expanded = permute((uint64_t)half_block, DES_E, DES_SUBKEY_BITS, DES_HALF_BLOCK_BITS);

    /* 2. Unico punto en el que la clave entra en el cifrado. El XOR es
     *    trivialmente invertible, por eso la seguridad depende del paso 3. */
    const uint64_t mixed = expanded ^ (round_key & DES_SUBKEY_MASK);

    /* 3. Sustitucion no lineal: 48 -> 32 bits. */
    const uint32_t substituted = substitute(mixed);

    /* 4. Permutacion P: dispersa la salida de cada caja hacia cajas distintas
     *    en la ronda siguiente. Sin este paso la difusion no saldria de los
     *    cuatro bits producidos por cada S-box. */
    return (uint32_t)permute((uint64_t)substituted, DES_P, DES_HALF_BLOCK_BITS, DES_HALF_BLOCK_BITS);
}
