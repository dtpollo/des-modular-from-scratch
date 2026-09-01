/*
 * test_des.c - Suite de pruebas de la primitiva de bloque DES.
 *
 * Cubre tres niveles, de menor a mayor abstraccion:
 *   1. Consistencia de las tablas (los datos son correctos por si mismos).
 *   2. Key schedule contra los valores intermedios publicados en FIPS 46-3.
 *   3. Vectores de prueba conocidos y propiedades algebraicas del cifrado.
 *
 * No se usa ningun framework externo a proposito: el proyecto no debe tener
 * dependencias para compilar y ejecutar sus tests.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "des.h"
#include "des_keyschedule.h"
#include "des_tables.h"

/* -------------------------------------------------------------------------
 * Mini-arnes de pruebas
 * ------------------------------------------------------------------------- */

static unsigned g_checks_run;
static unsigned g_checks_failed;

static void expect_u64(const char *label, uint64_t actual, uint64_t expected)
{
    ++g_checks_run;

    if (actual == expected) {
        printf("  [ ok ] %s\n", label);
    } else {
        ++g_checks_failed;
        printf("  [FAIL] %s\n", label);
        printf("         esperado: %016" PRIX64 "\n", expected);
        printf("         obtenido: %016" PRIX64 "\n", actual);
    }
}

static void expect_true(const char *label, int condition)
{
    ++g_checks_run;

    if (condition) {
        printf("  [ ok ] %s\n", label);
    } else {
        ++g_checks_failed;
        printf("  [FAIL] %s\n", label);
    }
}

/* -------------------------------------------------------------------------
 * 1. Consistencia de las tablas
 *
 * Un error de transcripcion en una tabla produce un cifrado que "funciona"
 * (es reversible) pero es incompatible con el estandar. Validar las tablas por
 * separado hace que ese fallo se detecte donde esta, no 16 rondas mas tarde.
 * ------------------------------------------------------------------------- */

/* Copia local del helper de permutacion: el test debe poder razonar sobre las
 * tablas sin depender de los detalles internos de ningun modulo. */
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

/* Comprueba que una tabla solo contiene indices validos (1..in_bits). */
static int table_indices_in_range(const uint8_t *table, unsigned length,
                                  unsigned in_bits)
{
    for (unsigned i = 0; i < length; ++i) {
        if (table[i] < 1 || table[i] > in_bits) {
            return 0;
        }
    }

    return 1;
}

/* Comprueba que una tabla es una permutacion pura: cada indice de 1..length
 * aparece exactamente una vez. Solo aplica a IP, IP_INV y P (no a E, que
 * duplica bits, ni a PC-1/PC-2, que descartan). */
static int table_is_bijection(const uint8_t *table, unsigned length)
{
    unsigned char seen[DES_BLOCK_BITS + 1] = { 0 };

    for (unsigned i = 0; i < length; ++i) {
        if (table[i] < 1 || table[i] > length || seen[table[i]] != 0) {
            return 0;
        }
        seen[table[i]] = 1;
    }

    return 1;
}

static void test_tables(void)
{
    puts("Tablas del estandar");

    expect_true("IP es una permutacion de 64 bits",
                table_is_bijection(DES_IP, DES_BLOCK_BITS));
    expect_true("IP_INV es una permutacion de 64 bits",
                table_is_bijection(DES_IP_INV, DES_BLOCK_BITS));
    expect_true("P es una permutacion de 32 bits",
                table_is_bijection(DES_P, DES_HALF_BLOCK_BITS));
    expect_true("E indexa solo bits validos de la mitad derecha",
                table_indices_in_range(DES_E, DES_SUBKEY_BITS, DES_HALF_BLOCK_BITS));
    expect_true("PC-1 indexa solo bits validos de la clave",
                table_indices_in_range(DES_PC1, DES_KEY_BITS_EFFECTIVE, DES_KEY_BITS));
    expect_true("PC-2 indexa solo bits validos de C||D",
                table_indices_in_range(DES_PC2, DES_SUBKEY_BITS,
                                       DES_KEY_BITS_EFFECTIVE));

    /* IP_INV debe deshacer IP exactamente; si no, el cifrado seguiria siendo
     * reversible pero no seria DES. */
    const uint64_t sample = UINT64_C(0x0123456789ABCDEF);
    const uint64_t round_trip = permute(permute(sample, DES_IP,
                                                DES_BLOCK_BITS, DES_BLOCK_BITS),
                                        DES_IP_INV, DES_BLOCK_BITS, DES_BLOCK_BITS);
    expect_u64("IP_INV(IP(x)) == x", round_trip, sample);

    /* Las 16 rotaciones deben sumar exactamente los 28 bits de C y D: es lo
     * que garantiza que el key schedule sea ciclico y que, por tanto, las
     * mismas subclaves sirvan para cifrar y descifrar. */
    unsigned shift_total = 0;
    for (unsigned i = 0; i < DES_ROUNDS; ++i) {
        shift_total += DES_SHIFTS[i];
    }
    expect_true("las rotaciones suman 28 (C y D vuelven al estado inicial)",
                shift_total == DES_KEY_HALF_BITS);

    putchar('\n');
}

/* -------------------------------------------------------------------------
 * 2. Key schedule
 *
 * Valores intermedios del ejemplo de FIPS 46-3 para la clave 133457799BBCDFF1.
 * Verificar K1 y K16 detecta tanto un error en PC-1/PC-2 como una rotacion
 * mal acumulada.
 * ------------------------------------------------------------------------- */

static void test_key_schedule(void)
{
    puts("Key schedule (clave 133457799BBCDFF1)");

    uint64_t round_keys[DES_ROUNDS];
    des_generate_round_keys(UINT64_C(0x133457799BBCDFF1), round_keys);

    expect_u64("K1  == 1B02EFFC7072", round_keys[0], UINT64_C(0x1B02EFFC7072));
    expect_u64("K16 == CB3D8B0E17F5", round_keys[15], UINT64_C(0xCB3D8B0E17F5));

    /* Ninguna subclave debe desbordar los 48 bits. */
    int within_48_bits = 1;
    for (unsigned i = 0; i < DES_ROUNDS; ++i) {
        if (round_keys[i] >> DES_SUBKEY_BITS) {
            within_48_bits = 0;
        }
    }
    expect_true("todas las subclaves caben en 48 bits", within_48_bits);

    /* Los bits de paridad (posiciones 8, 16, ..., 64) no participan: cambiarlos
     * debe producir exactamente el mismo juego de subclaves. */
    uint64_t flipped_parity[DES_ROUNDS];
    des_generate_round_keys(UINT64_C(0x133457799BBCDFF1) ^ UINT64_C(0x0101010101010101),
                            flipped_parity);

    int identical = 1;
    for (unsigned i = 0; i < DES_ROUNDS; ++i) {
        if (flipped_parity[i] != round_keys[i]) {
            identical = 0;
        }
    }
    expect_true("los bits de paridad no afectan a las subclaves", identical);

    putchar('\n');
}

/* -------------------------------------------------------------------------
 * 3. Vectores de prueba conocidos
 * ------------------------------------------------------------------------- */

typedef struct {
    const char *name;
    uint64_t    key;
    uint64_t    plaintext;
    uint64_t    ciphertext;
} des_test_vector_t;

static const des_test_vector_t k_vectors[] = {
    {
        /* Vector oficial de FIPS 46-3 / ejemplo canonico del estandar. */
        "FIPS 46-3",
        UINT64_C(0x133457799BBCDFF1),
        UINT64_C(0x0123456789ABCDEF),
        UINT64_C(0x85E813540F0AB405)
    },
    {
        /* Caso limite: clave y texto claro todo ceros. */
        "clave y bloque a cero",
        UINT64_C(0x0000000000000000),
        UINT64_C(0x0000000000000000),
        UINT64_C(0x8CA64DE9C1B123A7)
    },
    {
        /* Caso limite opuesto: todos los bits a uno. */
        "clave y bloque a unos",
        UINT64_C(0xFFFFFFFFFFFFFFFF),
        UINT64_C(0xFFFFFFFFFFFFFFFF),
        UINT64_C(0x7359B2163E4EDC58)
    }
};

static void test_known_vectors(void)
{
    puts("Vectores de prueba conocidos");

    const size_t vector_count = sizeof k_vectors / sizeof k_vectors[0];

    for (size_t i = 0; i < vector_count; ++i) {
        const des_test_vector_t *v = &k_vectors[i];
        char label[96];

        snprintf(label, sizeof label, "%s: cifrado", v->name);
        expect_u64(label, des_encrypt_block(v->plaintext, v->key), v->ciphertext);

        snprintf(label, sizeof label, "%s: descifrado", v->name);
        expect_u64(label, des_decrypt_block(v->ciphertext, v->key), v->plaintext);
    }

    putchar('\n');
}

/* -------------------------------------------------------------------------
 * 4. Propiedades algebraicas
 * ------------------------------------------------------------------------- */

/* Generador congruencial lineal: no es aleatorio de calidad criptografica, y
 * no hace falta que lo sea. Lo que se busca es un barrido determinista y
 * reproducible del espacio de entradas, no entropia. */
static uint64_t lcg_next(uint64_t *state)
{
    *state = (*state * UINT64_C(6364136223846793005)) + UINT64_C(1442695040888963407);
    return *state;
}

static void test_properties(void)
{
    puts("Propiedades de la red de Feistel");

    /* El descifrado debe deshacer el cifrado para cualquier par (bloque, clave). */
    uint64_t state = UINT64_C(0x123456789ABCDEF0);
    int round_trip_ok = 1;

    for (unsigned i = 0; i < 1000; ++i) {
        const uint64_t block = lcg_next(&state);
        const uint64_t key   = lcg_next(&state);

        if (des_decrypt_block(des_encrypt_block(block, key), key) != block) {
            round_trip_ok = 0;
            break;
        }
    }
    expect_true("decrypt(encrypt(x)) == x en 1000 pares pseudoaleatorios",
                round_trip_ok);

    /* Efecto avalancha: cambiar un solo bit del texto claro debe alterar
     * aproximadamente la mitad de los bits del criptograma. Se exige un rango
     * amplio (20-44 de 64) porque es una propiedad estadistica, no exacta. */
    const uint64_t key = UINT64_C(0x133457799BBCDFF1);
    const uint64_t base = UINT64_C(0x0123456789ABCDEF);
    const uint64_t base_cipher = des_encrypt_block(base, key);

    unsigned min_diff = DES_BLOCK_BITS;
    unsigned max_diff = 0;

    for (unsigned bit = 0; bit < DES_BLOCK_BITS; ++bit) {
        const uint64_t altered = des_encrypt_block(base ^ (UINT64_C(1) << bit), key);
        uint64_t delta = base_cipher ^ altered;

        unsigned diff = 0;
        while (delta != 0) {
            diff += (unsigned)(delta & UINT64_C(1));
            delta >>= 1;
        }

        if (diff < min_diff) { min_diff = diff; }
        if (diff > max_diff) { max_diff = diff; }
    }

    printf("         bits alterados por cada flip: min=%u, max=%u (ideal ~32)\n",
           min_diff, max_diff);
    expect_true("efecto avalancha dentro del rango esperado",
                min_diff >= 20 && max_diff <= 44);

    /* Cifrar con dos claves distintas el mismo bloque no puede dar lo mismo
     * (comprobacion de que la clave realmente entra en el calculo). */
    expect_true("claves distintas producen criptogramas distintos",
                des_encrypt_block(base, key) !=
                des_encrypt_block(base, key ^ UINT64_C(0x0000000000000002)));

    putchar('\n');
}

/* -------------------------------------------------------------------------
 * Punto de entrada
 * ------------------------------------------------------------------------- */

int main(void)
{
    puts("== Suite de pruebas DES ==\n");

    test_tables();
    test_key_schedule();
    test_known_vectors();
    test_properties();

    printf("Resultado: %u/%u comprobaciones superadas\n",
           g_checks_run - g_checks_failed, g_checks_run);

    if (g_checks_failed != 0) {
        printf("FALLARON %u comprobaciones\n", g_checks_failed);
        return EXIT_FAILURE;
    }

    puts("Todas las comprobaciones pasaron.");
    return EXIT_SUCCESS;
}
