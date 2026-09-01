/*
 * des_tables.h - Tablas constantes definidas por el estandar DES (FIPS 46-3).
 *
 * Este modulo es DELIBERADAMENTE solo datos: no expone ni una sola funcion.
 * Motivo: las tablas son parte de la especificacion y nunca cambian, mientras
 * que la logica que las consume (key schedule, funcion de Feistel, primitiva de
 * bloque) si puede evolucionar. Manteniendolas aisladas cualquier modulo puede
 * leerlas sin arrastrar dependencias de comportamiento.
 *
 * Convencion de indices (importante para entender todo el proyecto):
 * el estandar numera los bits desde 1 y considera que el bit 1 es el MAS
 * significativo. Por eso las tablas se almacenan tal cual aparecen en el
 * documento oficial, sin restarles 1, y la conversion a desplazamientos se hace
 * en el unico lugar donde se aplica una permutacion.
 */

#ifndef DES_TABLES_H
#define DES_TABLES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Parametros estructurales del algoritmo. Se declaran aqui porque describen
 * las dimensiones de las tablas, no el comportamiento de ningun modulo. */
#define DES_ROUNDS            16  /* Rondas de Feistel.                       */
#define DES_BLOCK_BITS        64  /* Tamano de bloque.                        */
#define DES_KEY_BITS          64  /* Clave tal como la entrega el usuario.    */
#define DES_KEY_BITS_EFFECTIVE 56 /* Clave real: PC-1 descarta 8 bits paridad.*/
#define DES_HALF_BLOCK_BITS   32  /* Mitades L y R.                           */
#define DES_SUBKEY_BITS       48  /* Subclave por ronda y salida de E.        */
#define DES_KEY_HALF_BITS     28  /* Registros C y D del key schedule.        */

#define DES_SBOX_COUNT         8  /* S1..S8.                                  */
#define DES_SBOX_ROWS          4  /* Seleccionadas por los bits externos.     */
#define DES_SBOX_COLS         16  /* Seleccionadas por los 4 bits internos.   */

/* Permutacion inicial: reordena los 64 bits del bloque antes de la primera
 * ronda. No aporta seguridad criptografica; proviene del cableado del hardware
 * de los anos 70, pero es obligatoria para interoperar. */
extern const uint8_t DES_IP[DES_BLOCK_BITS];

/* Permutacion final, inversa exacta de DES_IP. Se aplica tras la ronda 16. */
extern const uint8_t DES_IP_INV[DES_BLOCK_BITS];

/* Expansion E: 32 -> 48 bits. Duplica los bits de los bordes de cada grupo de
 * 4 para que un mismo bit alimente dos S-boxes distintas (efecto avalancha). */
extern const uint8_t DES_E[DES_SUBKEY_BITS];

/* Permutacion P: baraja los 32 bits que salen de las S-boxes para que los 4
 * bits producidos por una S-box se dispersen hacia S-boxes distintas en la
 * ronda siguiente. Es la pieza que convierte la difusion local en global. */
extern const uint8_t DES_P[DES_HALF_BLOCK_BITS];

/* PC-1: 64 -> 56 bits. Descarta los 8 bits de paridad (8, 16, ..., 64) y
 * reparte el resto en los registros C0 (bits 1..28) y D0 (bits 29..56). */
extern const uint8_t DES_PC1[DES_KEY_BITS_EFFECTIVE];

/* PC-2: 56 -> 48 bits. Comprime C_i || D_i en la subclave de la ronda; los 8
 * bits descartados hacen que cada ronda use un subconjunto distinto. */
extern const uint8_t DES_PC2[DES_SUBKEY_BITS];

/* Rotaciones izquierdas acumulables por ronda para C y D. Suman 28, de modo
 * que tras la ronda 16 los registros vuelven a su estado inicial: por eso el
 * mismo key schedule sirve para cifrar y para descifrar. */
extern const uint8_t DES_SHIFTS[DES_ROUNDS];

/* Las 8 cajas de sustitucion, unica parte no lineal de DES. Indexadas como
 * DES_SBOX[caja][fila][columna]; cada entrada es un valor de 4 bits. */
extern const uint8_t DES_SBOX[DES_SBOX_COUNT][DES_SBOX_ROWS][DES_SBOX_COLS];

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DES_TABLES_H */
