/*
 * des.c - Primitiva de bloque DES: IP -> 16 rondas de Feistel -> IP^-1.
 *
 * Este archivo contiene EXCLUSIVAMENTE la transformacion de un bloque de 64
 * bits. No incluye des_modes.h ni conoce padding, IV o encadenamiento: la
 * dependencia entre capas va en un solo sentido (modos -> primitiva), de modo
 * que ECB, CBC o cualquier otro modo podran anadirse sin tocar este nucleo.
 *
 * Estructura de la red de Feistel, para cada ronda i:
 *
 *     L_i = R_{i-1}
 *     R_i = L_{i-1} XOR f(R_{i-1}, K_i)
 *
 * La propiedad clave es que f NO necesita ser invertible: para deshacer una
 * ronda basta con conocer K_i, porque L_{i-1} = R_i XOR f(L_i, K_i). De ahi
 * que cifrar y descifrar compartan exactamente el mismo codigo y solo difieran
 * en el orden en que se consumen las subclaves.
 */

#include "des.h"

#include <stdint.h>
#include <string.h>

#include "des_feistel.h"
#include "des_keyschedule.h"
#include "des_tables.h"

/* Mascara de 32 bits usada para extraer la mitad derecha del bloque. */
#define DES_HALF_MASK UINT64_C(0xFFFFFFFF)

/* Direccion en la que se recorren las subclaves. Un enum explicito resulta
 * mas legible en las llamadas que un `bool reverse` sin nombre. */
typedef enum {
    DES_KEY_ORDER_FORWARD = 0, /* K1..K16: cifrado.    */
    DES_KEY_ORDER_REVERSE = 1  /* K16..K1: descifrado. */
} des_key_order_t;

/*
 * Aplica una tabla de permutacion del estandar. Ver la nota en
 * des_keyschedule.c sobre por que el helper se repite por modulo.
 *
 * El estandar numera los bits desde 1 empezando por el MAS significativo, de
 * ahi el desplazamiento (in_bits - table[i]).
 */
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

/*
 * Borra material sensible de la pila.
 *
 * Un memset normal puede ser eliminado por el compilador cuando demuestra que
 * el buffer no se vuelve a leer ("dead store elimination"). Escribir a traves
 * de un puntero a volatile impide esa optimizacion. No es una defensa
 * completa (los valores pueden haber quedado en registros o en swap), pero es
 * la higiene minima esperable en codigo criptografico.
 */
static void secure_zero(void *buffer, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)buffer;

    while (length-- > 0) {
        *p++ = 0;
    }
}

/*
 * Nucleo compartido por cifrado y descifrado.
 *
 * block       Bloque de 64 bits de entrada.
 * round_keys  Las 16 subclaves ya derivadas.
 * order       Sentido en el que se aplican.
 */
static uint64_t des_process_block(uint64_t block,
                                  const uint64_t round_keys[static DES_ROUNDS],
                                  des_key_order_t order)
{
    /* Permutacion inicial. Historicamente servia para simplificar el cableado
     * de los buses de 8 bits del hardware original; criptograficamente es
     * irrelevante, pero omitirla rompe la interoperabilidad. */
    const uint64_t permuted = permute(block, DES_IP, DES_BLOCK_BITS, DES_BLOCK_BITS);

    uint32_t left  = (uint32_t)(permuted >> DES_HALF_BLOCK_BITS);
    uint32_t right = (uint32_t)(permuted & DES_HALF_MASK);

    for (unsigned round = 0; round < DES_ROUNDS; ++round) {
        const unsigned index = (order == DES_KEY_ORDER_REVERSE)
                             ? (DES_ROUNDS - 1 - round)
                             : round;

        const uint32_t previous_right = right;

        /* R_i = L_{i-1} XOR f(R_{i-1}, K_i);  L_i = R_{i-1} */
        right = left ^ des_feistel_f(right, round_keys[index]);
        left  = previous_right;
    }

    /* Intercambio final: el preoutput se forma como R16 || L16, no L16 || R16.
     * Este "swap" es lo que hace que la red sea simetrica y que descifrar sea
     * el mismo procedimiento con las subclaves invertidas. */
    const uint64_t preoutput = ((uint64_t)right << DES_HALF_BLOCK_BITS)
                             | (uint64_t)left;

    return permute(preoutput, DES_IP_INV, DES_BLOCK_BITS, DES_BLOCK_BITS);
}

/*
 * Fachada comun: deriva las subclaves, procesa el bloque y limpia el material
 * de clave antes de devolver el control.
 */
static uint64_t des_run(uint64_t block, uint64_t key, des_key_order_t order)
{
    uint64_t round_keys[DES_ROUNDS];

    des_generate_round_keys(key, round_keys);
    const uint64_t result = des_process_block(block, round_keys, order);

    secure_zero(round_keys, sizeof round_keys);

    return result;
}

uint64_t des_encrypt_block(uint64_t block, uint64_t key)
{
    return des_run(block, key, DES_KEY_ORDER_FORWARD);
}

uint64_t des_decrypt_block(uint64_t block, uint64_t key)
{
    return des_run(block, key, DES_KEY_ORDER_REVERSE);
}
