/*
 * main.c - Demostracion de uso de la primitiva de bloque DES.
 *
 * Cifra y descifra un unico bloque de 64 bits e imprime los resultados. Sin
 * argumentos usa el vector de ejemplo de FIPS 46-3; opcionalmente admite una
 * clave y un bloque en hexadecimal para experimentar.
 *
 * Uso:
 *     des_demo [clave_hex] [bloque_hex]
 *
 * Ejemplo:
 *     des_demo 133457799BBCDFF1 0123456789ABCDEF
 */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "des.h"

/* Valores por defecto: el ejemplo canonico del estandar. */
#define DEFAULT_KEY   UINT64_C(0x133457799BBCDFF1)
#define DEFAULT_BLOCK UINT64_C(0x0123456789ABCDEF)

/* Un uint64_t no puede representarse con mas de 16 digitos hexadecimales. */
#define MAX_HEX_DIGITS 16

/*
 * Convierte una cadena hexadecimal en un uint64_t.
 *
 * Se valida de forma estricta en lugar de confiar en strtoull a secas, porque
 * esa funcion acepta silenciosamente entradas indeseadas: cadenas vacias,
 * signos, espacios iniciales o prefijos "0x". Para una utilidad de linea de
 * comandos es preferible rechazar la entrada a cifrar un valor que el usuario
 * no queria.
 *
 * Devuelve 0 si la conversion tuvo exito, -1 en caso de error.
 */
static int parse_hex_u64(const char *text, uint64_t *out)
{
    if (text == NULL || out == NULL) {
        return -1;
    }

    size_t digits = 0;
    for (const char *p = text; *p != '\0'; ++p) {
        const char c = *p;
        const int is_hex = (c >= '0' && c <= '9')
                        || (c >= 'a' && c <= 'f')
                        || (c >= 'A' && c <= 'F');
        if (!is_hex) {
            return -1;
        }
        ++digits;
    }

    if (digits == 0 || digits > MAX_HEX_DIGITS) {
        return -1;
    }

    /* Llegados aqui la cadena solo contiene digitos hexadecimales y cabe en
     * 64 bits, asi que strtoull no puede desbordar. Aun asi se comprueba
     * errno: es la forma correcta de usar la API y protege ante cambios
     * futuros en la validacion previa. */
    errno = 0;
    char *end = NULL;
    const unsigned long long value = strtoull(text, &end, 16);

    if (errno != 0 || end == text || *end != '\0') {
        return -1;
    }

    *out = (uint64_t)value;
    return 0;
}

static void print_block(const char *label, uint64_t value)
{
    printf("  %-14s %016" PRIX64 "\n", label, value);
}

int main(int argc, char *argv[])
{
    uint64_t key   = DEFAULT_KEY;
    uint64_t block = DEFAULT_BLOCK;

    if (argc > 3) {
        fprintf(stderr, "Uso: %s [clave_hex] [bloque_hex]\n",
                argv[0] != NULL ? argv[0] : "des_demo");
        return EXIT_FAILURE;
    }

    if (argc >= 2 && parse_hex_u64(argv[1], &key) != 0) {
        fprintf(stderr, "Error: clave invalida '%s' "
                        "(se esperan 1-16 digitos hexadecimales).\n", argv[1]);
        return EXIT_FAILURE;
    }

    if (argc >= 3 && parse_hex_u64(argv[2], &block) != 0) {
        fprintf(stderr, "Error: bloque invalido '%s' "
                        "(se esperan 1-16 digitos hexadecimales).\n", argv[2]);
        return EXIT_FAILURE;
    }

    const uint64_t ciphertext = des_encrypt_block(block, key);
    const uint64_t recovered  = des_decrypt_block(ciphertext, key);

    puts("== Demostracion DES (un bloque de 64 bits) ==\n");
    print_block("Clave:", key);
    print_block("Texto claro:", block);
    print_block("Cifrado:", ciphertext);
    print_block("Descifrado:", recovered);
    putchar('\n');

    if (recovered != block) {
        /* No deberia ocurrir nunca: indicaria un fallo en la implementacion,
         * no en la entrada del usuario. */
        fprintf(stderr, "ERROR: el descifrado no recupero el texto claro.\n");
        return EXIT_FAILURE;
    }

    puts("El descifrado recupero el texto claro original.");
    puts("\nRecordatorio: DES no es seguro hoy en dia (clave efectiva de 56 "
         "bits).\nEste programa tiene unicamente fines educativos.");

    return EXIT_SUCCESS;
}
