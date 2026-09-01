/*
 * des_modes.c - Modos de operacion sobre la primitiva de bloque.
 *
 * PROXIMAMENTE: ECB/CBC.
 *
 * Sin implementacion todavia. El archivo queda intencionadamente vacio y
 * FUERA del build (ver la variable LIB_SRCS del Makefile), porque una unidad
 * de traduccion sin declaraciones es un error bajo -Wpedantic. Se incorporara
 * al Makefile en el mismo commit en el que se implemente el primer modo.
 *
 * Plan de implementacion:
 *   - ECB: cifra cada bloque de forma independiente. Se incluira solo como
 *     referencia didactica, con una advertencia visible: bloques de texto
 *     claro identicos producen bloques cifrados identicos, lo que filtra la
 *     estructura del mensaje.
 *   - CBC: encadena cada bloque con el anterior mediante XOR y requiere un IV
 *     impredecible y unico por mensaje.
 *   - Padding PKCS#7 y verificacion estricta al desempaquetar.
 *
 * Todo ello se construira usando unicamente des_encrypt_block y
 * des_decrypt_block, sin modificar una sola linea del nucleo del algoritmo.
 */
