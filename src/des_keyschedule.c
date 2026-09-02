/*
 * des_keyschedule.c - PC-1, rotaciones y PC-2 -> 16 subclaves de 48 bits.
 *
 * Flujo del algoritmo:
 *
 *     clave 64 bits
 *          | PC-1 (descarta paridad)
 *          v
 *     C0 (28) || D0 (28)
 *          | rotacion izquierda de DES_SHIFTS[i] bits, acumulativa
 *          v
 *     Ci (28) || Di (28)  ----- PC-2 ----->  Ki (48 bits)
 *
 * Este modulo no sabe nada de bloques, rondas de Feistel ni modos: solo
 * transforma clave en subclaves.
 */

#include "des_keyschedule.h"

#include <stdint.h>

#include "des_tables.h"

/*
 * Aplica una tabla de permutacion del estandar.
 *
 * El helper es `static` y vive en cada unidad de traduccion que lo necesita.
 * Es una decision consciente: mantiene a cada modulo sin dependencias de los
 * internos de otro, al coste de repetir cinco lineas. Si el proyecto crece,
 * el paso natural es promoverlo a una cabecera interna (ver docs/DESIGN.md).
 *
 * input     Valor de entrada, alineado a la derecha en `in_bits` bits.
 * table     Tabla 1-based del estandar; table[i] indica que bit de la entrada
 *           ocupa la posicion i de la salida.
 * out_bits  Numero de entradas de la tabla = ancho del resultado.
 * in_bits   Ancho logico de la entrada, necesario porque el estandar cuenta
 *           los bits desde el MAS significativo: el bit numero n esta en el
 *           desplazamiento (in_bits - n).
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
 * Rotacion circular a la izquierda sobre un registro de 28 bits.
 *
 * No se puede usar el desplazamiento nativo directamente: los tipos de C son
 * de 32 bits, asi que hay que reinyectar a mano los bits que se salen por la
 * izquierda y enmascarar despues para no dejar basura en los 4 bits altos.
 */
static uint32_t rotate_left_28(uint32_t half, unsigned amount)
{
    /* Convierte todos los bits a 1 desde la posicion marcada con 1:
     * 0001 0000 0000 0000 0000 0000 0000 0000 
     * 0000 1111 1111 1111 1111 1111 1111 1111 */
    const uint32_t mask = (UINT32_C(1) << DES_KEY_HALF_BITS) - 1;

    /* `amount` siempre vale 1 o 2 (ver DES_SHIFTS)*/
    return ((half << amount) | (half >> (DES_KEY_HALF_BITS - amount))) & mask;
}

void des_generate_round_keys(uint64_t key, uint64_t round_keys[static DES_ROUNDS])
{
    /* PC-1 reduce la clave a los 56 bits */
    const uint64_t permuted_key = permute(key, DES_PC1, DES_KEY_BITS_EFFECTIVE, DES_KEY_BITS);

    /* Convierte todos los bits a 1 desde la posicion marcada con 1:
     * 0001 0000 0000 0000 0000 0000 0000 0000 
     * 0000 1111 1111 1111 1111 1111 1111 1111 */
    const uint32_t half_mask = (UINT32_C(1) << DES_KEY_HALF_BITS) - 1;

    /* Los 56 bits se parten en dos registros de 28 que se rotan por separado.
     * C es la mitad alta del resultado de PC-1, D la mitad baja. */
    uint32_t c = (uint32_t)((permuted_key >> DES_KEY_HALF_BITS) & half_mask);
    uint32_t d = (uint32_t)(permuted_key & half_mask);

    for (unsigned round = 0; round < DES_ROUNDS; ++round) {
        /* Las rotaciones son acumulativas, por eso en total rota 28 posiciones. */
        c = rotate_left_28(c, DES_SHIFTS[round]);
        d = rotate_left_28(d, DES_SHIFTS[round]);

        /* PC-2 opera sobre la concatenacion C_i || D_i vista como un unico
         * valor de 56 bits, que es la numeracion que asume la tabla. */
        const uint64_t combined = ((uint64_t)c << DES_KEY_HALF_BITS) | (uint64_t)d;

        round_keys[round] = permute(combined, DES_PC2, DES_SUBKEY_BITS, DES_KEY_BITS_EFFECTIVE);
    }
}
