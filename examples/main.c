/*
 * main.c - Demostracion de uso de la primitiva de bloque DES.
 *
 * Toma un texto normal, lo cifra y lo descifra, para ver la API funcionando
 * con algo mas tangible que un numero hexadecimal suelto.
 *
 * Uso:
 *     des_demo ["texto a cifrar"]
 *
 * Si no se pasa texto, se usa una frase por defecto.
 *
 * IMPORTANTE: este programa cifra varios bloques en un simple bucle, cada uno
 * de forma independiente. Eso es, por definicion, el modo ECB, y ECB filtra
 * patrones del texto claro (bloques identicos producen cifrados identicos).
 * Aqui es aceptable porque el unico objetivo es DEMOSTRAR la primitiva de
 * bloque; no uses este patron para cifrar nada real. Los modos de operacion
 * correctos (con encadenamiento e IV) llegaran en des_modes.c.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "des.h"

/* Clave fija de ejemplo (el vector canonico de FIPS 46-3). En un programa
 * real la clave nunca se escribe en el codigo fuente. */
#define DEMO_KEY UINT64_C(0x133457799BBCDFF1)

/* DES cifra bloques de 64 bits = 8 bytes. */
#define BLOCK_BYTES 8

/* Limite arbitrario para no complicar el ejemplo con memoria dinamica. */
#define MAX_TEXT_LEN 1024

static const char *k_default_text = "Hola, DES desde C!";

/*
 * Empaqueta 8 bytes en un uint64_t, big-endian: el primer byte del bloque
 * ocupa los bits mas significativos. Es la misma convencion que usa
 * des_encrypt_block para el bit 1 del estandar, asi que el orden de los
 * caracteres se conserva al imprimir el valor en hexadecimal.
 */
static uint64_t bytes_to_block(const uint8_t bytes[BLOCK_BYTES])
{
    uint64_t block = 0;

    for (int i = 0; i < BLOCK_BYTES; ++i) {
        block = (block << 8) | bytes[i];
    }

    return block;
}

/* Operacion inversa a bytes_to_block. */
static void block_to_bytes(uint64_t block, uint8_t bytes[BLOCK_BYTES])
{
    for (int i = BLOCK_BYTES - 1; i >= 0; --i) {
        bytes[i] = (uint8_t)(block & 0xFFu);
        block >>= 8;
    }
}

int main(int argc, char *argv[])
{
    const char *text = (argc >= 2) ? argv[1] : k_default_text;
    const size_t text_len = strlen(text);

    if (text_len == 0 || text_len >= MAX_TEXT_LEN) {
        fprintf(stderr,
                "Error: el texto debe medir entre 1 y %d caracteres.\n",
                MAX_TEXT_LEN - 1);
        return 1;
    }

    /* Numero de bloques de 8 bytes necesarios para cubrir el texto,
     * redondeando hacia arriba (division entera + resto). */
    const size_t block_count = (text_len / BLOCK_BYTES) + 1;
    const size_t padded_len  = block_count * BLOCK_BYTES;

    /* Buffer de trabajo relleno con ceros: el ultimo bloque casi nunca llena
     * los 8 bytes completos, y el relleno con '\0' hace que, al reconstruir
     * el texto, printf("%s", ...) se detenga justo donde terminaba el texto
     * original sin necesidad de quitar el relleno a mano. */
    uint8_t plain_buffer[MAX_TEXT_LEN]     = { 0 };
    uint8_t recovered_buffer[MAX_TEXT_LEN] = { 0 };
    memcpy(plain_buffer, text, text_len);

    printf("== Demostracion DES (texto de ejemplo) ==\n\n");
    printf("Texto original (%zu bytes): \"%s\"\n", text_len, text);
    printf("Clave de ejemplo:            %016" PRIX64 "\n", (uint64_t)DEMO_KEY);
    printf("Bloques de 64 bits a cifrar: %zu\n\n", block_count);

    for (size_t i = 0; i < block_count; ++i) {
        const uint64_t plain_block  = bytes_to_block(&plain_buffer[i * BLOCK_BYTES]);
        const uint64_t cipher_block = des_encrypt_block(plain_block, DEMO_KEY);
        const uint64_t back_block   = des_decrypt_block(cipher_block, DEMO_KEY);

        printf("  bloque %zu  claro=%016" PRIX64 "  cifrado=%016" PRIX64 "\n",
               i, plain_block, cipher_block);

        block_to_bytes(back_block, &recovered_buffer[i * BLOCK_BYTES]);
    }

    (void)padded_len; /* solo documenta el tamano del buffer, no se usa mas */

    printf("\nTexto recuperado tras descifrar: \"%s\"\n", recovered_buffer);

    if (memcmp(plain_buffer, recovered_buffer, text_len) != 0) {
        /* No deberia ocurrir nunca: indicaria un fallo en la implementacion,
         * no en la entrada del usuario. */
        fprintf(stderr, "\nERROR: el texto recuperado no coincide con el original.\n");
        return 1;
    }

    printf("\nEl texto se recupero exactamente igual. \n");

    return 0;
}
