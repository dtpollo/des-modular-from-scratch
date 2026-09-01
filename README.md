# des-c

Implementación desde cero del **Data Encryption Standard (DES)** en C11, sin
dependencias externas, con una arquitectura modular que separa el núcleo del
algoritmo de los futuros modos de operación.

> ⚠️ **DES es criptográficamente inseguro.** Su clave efectiva de 56 bits se
> rompe por fuerza bruta con hardware moderno; NIST lo retiró formalmente en
> 2005. Este proyecto tiene **fines exclusivamente educativos**. Para software
> real usa AES-GCM o ChaCha20-Poly1305 a través de una biblioteca auditada
> (libsodium, OpenSSL).

---

## Qué hace

Implementa la primitiva de bloque de DES tal y como la define
[FIPS PUB 46-3](https://csrc.nist.gov/pubs/fips/46-3/final): cifrado y
descifrado de bloques de 64 bits con claves de 64 bits (56 efectivos).

- Permutación inicial y final (`IP` / `IP⁻¹`).
- Key schedule completo: `PC-1` → rotaciones → `PC-2` → 16 subclaves de 48 bits.
- Función de ronda de Feistel: expansión `E`, XOR con la subclave, 8 S-boxes y
  permutación `P`.
- 16 rondas, con descifrado por inversión del orden de las subclaves.

**Lo que deliberadamente *no* hace (todavía):** padding, encadenamiento de
bloques, vectores de inicialización. Todo eso pertenece a los modos de
operación, que se implementarán en `des_modes.c` **sin modificar el núcleo**.
Ver [docs/DESIGN.md](docs/DESIGN.md) para el razonamiento completo.

---

## Estructura

```
des-c/
├── include/          Cabeceras públicas e internas
│   ├── des_tables.h        Tablas del estándar (solo datos)
│   ├── des_keyschedule.h   Derivación de subclaves
│   ├── des_feistel.h       Función de ronda f(R, K)
│   ├── des.h               API pública
│   └── des_modes.h         ECB/CBC — próximamente
├── src/              Implementación
├── tests/            Suite de pruebas sin dependencias
├── examples/         Programa de demostración
├── docs/DESIGN.md    Diseño, teoría y decisiones de arquitectura
└── Makefile
```

Las dependencias fluyen en una sola dirección: los modos dependerán de la
primitiva, nunca al revés.

---

## Compilación

Requiere un compilador de C11 (GCC o Clang) y `make`. Sin dependencias.

```bash
make            # compila la biblioteca, los tests y el ejemplo
make test       # compila y ejecuta la suite de pruebas
make examples   # compila y ejecuta la demostración
make clean      # elimina build/
```

Los artefactos se generan bajo `build/`; el árbol de fuentes nunca se ensucia.

### Ejecutar los tests

```bash
$ make test
== Suite de pruebas DES ==

Tablas del estándar
  [ ok ] IP es una permutacion de 64 bits
  ...

Vectores de prueba conocidos
  [ ok ] FIPS 46-3: cifrado
  [ ok ] FIPS 46-3: descifrado
  ...

Resultado: N/N comprobaciones superadas
Todas las comprobaciones pasaron.
```

El binario devuelve un código de salida distinto de cero si algo falla, así que
puede usarse tal cual en CI.

Cubre cuatro niveles: consistencia de las tablas, key schedule contra los
valores intermedios de FIPS 46-3 (K1 y K16), vectores de prueba conocidos
—incluido el oficial— y propiedades algebraicas (round-trip sobre 1000 pares
y efecto avalancha).

### Ejecutar la demostración

```bash
$ make examples
```

O directamente, con clave y bloque propios en hexadecimal:

```bash
$ ./build/bin/des_demo 133457799BBCDFF1 0123456789ABCDEF
== Demostracion DES (un bloque de 64 bits) ==

  Clave:         133457799BBCDFF1
  Texto claro:   0123456789ABCDEF
  Cifrado:       85E813540F0AB405
  Descifrado:    0123456789ABCDEF
```

---

## Uso de la API

La superficie pública son dos funciones:

```c
#include "des.h"

uint64_t des_encrypt_block(uint64_t block, uint64_t key);
uint64_t des_decrypt_block(uint64_t block, uint64_t key);
```

Ejemplo mínimo:

```c
#include <inttypes.h>
#include <stdio.h>
#include "des.h"

int main(void)
{
    const uint64_t key   = UINT64_C(0x133457799BBCDFF1);
    const uint64_t plain = UINT64_C(0x0123456789ABCDEF);

    const uint64_t cipher    = des_encrypt_block(plain, key);
    const uint64_t recovered = des_decrypt_block(cipher, key);

    printf("cifrado:    %016" PRIX64 "\n", cipher);     /* 85E813540F0AB405 */
    printf("descifrado: %016" PRIX64 "\n", recovered);  /* 0123456789ABCDEF */

    return 0;
}
```

Compilación manual:

```bash
cc -std=c11 -Iinclude mi_programa.c src/des_tables.c src/des_keyschedule.c \
   src/des_feistel.c src/des.c -o mi_programa
```

### Notas de uso

- Los bloques se tratan como enteros de 64 bits donde **el bit 1 del estándar
  es el bit más significativo**.
- Los 8 bits de paridad de la clave (posiciones 8, 16, …, 64) se ignoran: no
  se valida su paridad porque el estándar no lo exige para operar.
- Ambas funciones son **puras y reentrantes**: sin estado global, seguras de
  llamar desde varios hilos.
- Cifrar varios bloques con llamadas sucesivas equivale a **ECB**, que filtra
  patrones del texto claro. No lo hagas: espera a los modos de operación.

---

## Limitaciones conocidas

- **No es resistente a canales laterales.** Los accesos a las S-boxes dependen
  de los datos, por lo que la implementación no es de tiempo constante y es,
  en principio, vulnerable a ataques de temporización por caché.
- No hay detección de claves débiles ni semidébiles.
- No hay soporte para Triple DES.
- Solo bloques individuales; sin API orientada a buffers.

Estas limitaciones son aceptables para el propósito del proyecto —enseñar cómo
funciona DES— y están documentadas en lugar de silenciadas.

---

## Referencias

- [FIPS PUB 46-3 — Data Encryption Standard](https://csrc.nist.gov/pubs/fips/46-3/final)
- [NIST SP 800-38A — Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [docs/DESIGN.md](docs/DESIGN.md) — teoría, rol de cada tabla y decisiones de
  arquitectura.

---

## Transparencia

Este código fue desarrollado con asistencia de IA y posteriormente revisado,
probado y validado por mí contra los vectores oficiales de FIPS 46-3.

---

## Licencia

[GPL-3.0](LICENSE) © 2026 Daniel Troya
