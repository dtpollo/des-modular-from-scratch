/*
 * des_modes.h - Modos de operacion sobre la primitiva de bloque.
 *
 * PROXIMAMENTE: ECB/CBC.
 *
 * Sin implementacion todavia. Esta cabecera existe para fijar la frontera
 * arquitectonica desde el primer commit: los modos se construiran ENCIMA de
 * des.h (des_encrypt_block / des_decrypt_block) y el nucleo del algoritmo
 * nunca incluira este archivo. La dependencia va en un solo sentido
 * (modos -> primitiva), de forma que anadir ECB, CBC, CTR o padding PKCS#7
 * no requerira tocar des.c, des_feistel.c ni des_keyschedule.c.
 */

#ifndef DES_MODES_H
#define DES_MODES_H

#ifdef __cplusplus
extern "C" {
#endif

/* Aqui iran las declaraciones de des_ecb_encrypt / des_cbc_encrypt y sus
 * inversas, junto con el manejo de padding y de vectores de inicializacion. */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DES_MODES_H */
