/*
 * des_feistel.h - Funcion de ronda f(R, K) de DES.
 *
 * Este modulo NO conoce el key schedule: recibe la subclave ya derivada como
 * un simple valor de 48 bits. Esa frontera es intencional. La funcion f es una
 * transformacion pura (mismos argumentos -> mismo resultado, sin estado ni
 * efectos secundarios), lo que la hace trivial de testear y reutilizable por
 * cualquier variante que quiera alimentarla con subclaves de otro origen.
 */

#ifndef DES_FEISTEL_H
#define DES_FEISTEL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Calcula f(half_block, round_key), el nucleo no lineal de cada ronda.
 *
 * Encadena las cuatro etapas definidas por el estandar:
 *   1. Expansion E:  32 -> 48 bits.
 *   2. XOR con la subclave de ronda (unico punto donde entra la clave).
 *   3. Sustitucion:  8 S-boxes, 48 -> 32 bits.
 *   4. Permutacion P: difusion de los bits resultantes.
 *
 * half_block  Mitad derecha R de 32 bits.
 * round_key   Subclave de 48 bits alineada a la derecha; los 16 bits altos se
 *             ignoran, de modo que un valor mal formado no corrompe el
 *             resultado de la expansion.
 *
 * Devuelve los 32 bits que se combinaran con XOR contra la mitad izquierda.
 */
uint32_t des_feistel_f(uint32_t half_block, uint64_t round_key);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DES_FEISTEL_H */
