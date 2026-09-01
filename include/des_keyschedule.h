/*
 * des_keyschedule.h - Derivacion de las 16 subclaves de ronda.
 *
 * El key schedule se expone como modulo propio porque es independiente del
 * dato a cifrar: solo depende de la clave. Separarlo permite (a) testearlo de
 * forma aislada contra los valores intermedios publicados en FIPS 46-3 y
 * (b) reutilizar las subclaves entre muchos bloques cuando en el futuro se
 * implementen modos de operacion, sin recalcularlas por bloque.
 */

#ifndef DES_KEYSCHEDULE_H
#define DES_KEYSCHEDULE_H

#include <stdint.h>

#include "des_tables.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Deriva las DES_ROUNDS subclaves de 48 bits a partir de una clave de 64 bits.
 *
 * key         Clave completa de 64 bits. Los 8 bits de paridad (posiciones
 *             8, 16, ..., 64) se ignoran: PC-1 no los selecciona, por lo que
 *             la entropia real es de 56 bits. No se valida la paridad porque
 *             el estandar no la exige para operar.
 * round_keys  Buffer de salida de exactamente DES_ROUNDS elementos. Cada
 *             subclave queda alineada a la derecha en los 48 bits bajos; los
 *             16 bits altos siempre son cero.
 *
 * El parametro se declara con `static DES_ROUNDS` (C99) para documentar en el
 * propio tipo que el puntero no puede ser nulo y debe apuntar a al menos 16
 * elementos; varios compiladores lo aprovechan para diagnosticar errores.
 */
void des_generate_round_keys(uint64_t key, uint64_t round_keys[static DES_ROUNDS]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DES_KEYSCHEDULE_H */
