/*
 * des.h - API publica de la primitiva de bloque DES.
 *
 * ADVERTENCIA DE SEGURIDAD
 * ------------------------
 * DES esta criptograficamente roto: su clave efectiva de 56 bits es
 * vulnerable a busqueda exhaustiva con hardware moderno. Este codigo existe
 * con fines educativos y de referencia. Para software real usa AES-GCM,
 * ChaCha20-Poly1305 o una biblioteca auditada como libsodium u OpenSSL.
 *
 * ALCANCE
 * -------
 * Esta cabecera cubre unicamente la transformacion de UN bloque de 64 bits.
 * No hay padding, ni IV, ni encadenamiento: eso pertenece a los modos de
 * operacion (ver des_modes.h). Un bloque aislado cifrado con esta API es,
 * por definicion, ECB de un solo bloque; encadenar varios bloques asi filtra
 * patrones del texto claro y no debe hacerse.
 */

#ifndef DES_H
#define DES_H

#include <stdint.h>

#include "des_tables.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Cifra un unico bloque de 64 bits.
 *
 * block  Texto claro como entero de 64 bits, big-endian conceptual: el bit 1
 *        del estandar es el bit mas significativo de este valor.
 * key    Clave de 64 bits; los 8 bits de paridad se ignoran (ver
 *        des_generate_round_keys).
 *
 * Devuelve el bloque cifrado. La funcion es pura y reentrante: no mantiene
 * estado global, por lo que puede llamarse desde varios hilos a la vez.
 */
uint64_t des_encrypt_block(uint64_t block, uint64_t key);

/*
 * Descifra un unico bloque de 64 bits.
 *
 * Usa exactamente la misma red de Feistel que des_encrypt_block, pero aplica
 * las subclaves en orden inverso (K16..K1). Esa simetria es la propiedad
 * central de una red de Feistel: la funcion f no necesita ser invertible.
 *
 * Se cumple para todo par (block, key):
 *     des_decrypt_block(des_encrypt_block(block, key), key) == block
 */
uint64_t des_decrypt_block(uint64_t block, uint64_t key);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DES_H */
