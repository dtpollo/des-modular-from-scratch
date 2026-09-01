# Diseño e implementación

Documento de arquitectura de `des-c`. Explica qué es DES, cómo funciona cada
pieza del algoritmo, qué papel cumple cada tabla y —sobre todo— por qué el
código está organizado de esta forma y no de otra.

---

## 1. Qué es DES

El **Data Encryption Standard** es un cifrador por bloques publicado por el NBS
(hoy NIST) en 1977 y estandarizado finalmente en **FIPS PUB 46-3**. Sus
parámetros son:

| Parámetro           | Valor                                          |
| ------------------- | ---------------------------------------------- |
| Tamaño de bloque    | 64 bits                                        |
| Tamaño de clave     | 64 bits declarados, **56 bits efectivos**      |
| Estructura          | Red de Feistel                                 |
| Rondas              | 16                                             |
| Componente no lineal| 8 S-boxes de 6→4 bits                          |

Los 8 bits que faltan hasta los 64 son bits de paridad (posiciones 8, 16, …,
64) que la permutación PC-1 descarta. Esa clave de 56 bits es exactamente el
motivo por el que DES está muerto: el espacio de 2^56 claves se recorre por
fuerza bruta en horas con hardware dedicado, y ya se demostró públicamente en
1998 con la máquina *Deep Crack* de la EFF. DES fue formalmente retirado por
NIST en 2005.

Este proyecto existe para **entender** el algoritmo, no para proteger datos.

---

## 2. La estructura de Feistel

Una red de Feistel divide el bloque en dos mitades y, en cada ronda, aplica:

```
L_i = R_{i-1}
R_i = L_{i-1} XOR f(R_{i-1}, K_i)
```

La propiedad central —y la razón de que este diseño sea tan influyente— es que
**`f` no necesita ser invertible**. Para deshacer una ronda basta con reordenar
la ecuación:

```
R_{i-1} = L_i
L_{i-1} = R_i XOR f(L_i, K_i)
```

Es decir: descifrar es *exactamente el mismo procedimiento* aplicando las
subclaves en orden inverso. Eso permite que `f` sea todo lo compleja y no
lineal que haga falta (las S-boxes no son biyectivas: mapean 6 bits a 4), sin
tener que construir su inversa.

En el código, esa simetría se traduce en una sola función interna,
`des_process_block()`, parametrizada por un enum `des_key_order_t`. Cifrar y
descifrar comparten el 100 % de la lógica; solo cambia el sentido en que se
recorren las subclaves. Duplicar el bucle para el descifrado sería una fuente
silenciosa de bugs por divergencia.

### Flujo completo de un bloque

```
        bloque de 64 bits
               │
               ▼
        IP (permutación inicial)
               │
        ┌──────┴──────┐
       L0            R0            (32 bits cada uno)
        │             │
        │      ┌──────┴──────┐
        │      │  f(R, K_i)  │◄──── K_i (48 bits)
        │      └──────┬──────┘
        └────► XOR ◄──┘
               │
          (16 rondas)
               │
        R16 || L16                 ← intercambio final
               │
               ▼
        IP⁻¹ (permutación final)
               │
               ▼
        bloque cifrado
```

El **intercambio final** (`R16 || L16` en lugar de `L16 || R16`) no es un
detalle cosmético: es justamente lo que hace que la red sea simétrica y que el
descifrado pueda usar el mismo bucle.

---

## 3. La función de ronda `f`

`f(R, K)` encadena cuatro etapas:

### 3.1. Expansión E (32 → 48 bits)

Convierte la mitad derecha en 48 bits para poder combinarla con la subclave.
No inventa información: **duplica** 16 bits. Concretamente, cada grupo de 4
bits se rodea con el último bit del grupo anterior y el primero del siguiente.

Ese solape es la clave de la difusión: un bit del texto claro alimenta **dos
S-boxes distintas**, así que su influencia se duplica en cada ronda.

### 3.2. XOR con la subclave

Único punto de todo el algoritmo donde entra la clave. La operación es
trivialmente invertible; toda la fuerza criptográfica recae en el paso
siguiente.

### 3.3. Sustitución (48 → 32 bits)

Los 48 bits se parten en 8 bloques de 6, uno por S-box. Cada caja devuelve 4
bits. **Es el único componente no lineal de DES**: sin él, todo el cifrado
sería una función afín sobre GF(2) y se rompería con álgebra lineal.

El reparto de los 6 bits de entrada no es arbitrario:

- Los **bits externos** (el más significativo y el menos significativo)
  seleccionan la **fila** (0–3).
- Los **4 bits centrales** seleccionan la **columna** (0–15).

¿Por qué los externos para la fila? Porque son precisamente los bits que la
expansión E tomó prestados de los grupos vecinos. Al usarlos como selector de
fila, un único bit de entrada modifica el comportamiento de dos S-boxes
adyacentes, amplificando el efecto avalancha.

Además, cada una de las 4 filas de una S-box es una permutación completa de
0–15. Fijada la fila, la caja es biyectiva; la no linealidad surge de que filas
distintas dan permutaciones distintas. Este diseño no fue casual: las S-boxes
fueron construidas (con criterios que el NSA no publicó en su momento) para
resistir **criptoanálisis diferencial**, técnica que la comunidad académica no
redescubriría hasta 1990.

### 3.4. Permutación P (32 → 32 bits)

Baraja la salida de las S-boxes de forma que los 4 bits producidos por una caja
alimenten cajas **diferentes** en la ronda siguiente. Sin P, la difusión
quedaría confinada a los mismos 6 bits ronda tras ronda y el cifrado se
reduciría a 8 cifradores pequeños e independientes.

---

## 4. El key schedule

```
clave de 64 bits
     │ PC-1  (descarta los 8 bits de paridad)
     ▼
C0 (28 bits) ‖ D0 (28 bits)
     │ rotación izquierda de SHIFTS[i], acumulativa
     ▼
C_i ‖ D_i  ──── PC-2 (56 → 48) ────►  K_i
```

- **PC-1** selecciona 56 de los 64 bits. Ningún múltiplo de 8 aparece en la
  tabla: esos son los bits de paridad.
- **SHIFTS** define cuánto rota cada registro en cada ronda (1 o 2 posiciones).
  La suma de las 16 rotaciones es **exactamente 28**, así que tras la ronda 16
  `C` y `D` vuelven a su estado inicial. Por eso el key schedule es cíclico y
  las mismas 16 subclaves sirven para cifrar y descifrar.
- **PC-2** comprime `C_i ‖ D_i` a 48 bits descartando 8. Como los registros se
  rotan antes de cada compresión, cada ronda usa un subconjunto distinto de la
  clave.

La suite de pruebas verifica esta propiedad de forma explícita
(`las rotaciones suman 28`) y compara K1 y K16 contra los valores intermedios
publicados en el estándar.

---

## 5. Rol de cada tabla

| Tabla     | Dimensiones | Función |
| --------- | ----------- | ------- |
| `IP`      | 64 → 64     | Permutación inicial del bloque. Sin valor criptográfico; herencia del hardware de los 70. Obligatoria para interoperar. |
| `IP_INV`  | 64 → 64     | Inversa exacta de `IP`, aplicada tras la ronda 16. |
| `E`       | 32 → 48     | Expande la mitad derecha duplicando bits de los bordes. Origen de la difusión entre S-boxes. |
| `SBOX`    | 8×4×16      | Sustitución no lineal 6 → 4 bits. El corazón de la seguridad de DES. |
| `P`       | 32 → 32     | Dispersa la salida de cada S-box hacia cajas distintas en la ronda siguiente. |
| `PC1`     | 64 → 56     | Elimina los bits de paridad y forma `C0 ‖ D0`. |
| `PC2`     | 56 → 48     | Comprime `C_i ‖ D_i` en la subclave de ronda. |
| `SHIFTS`  | 16          | Rotaciones por ronda de `C` y `D`. |

---

## 6. Arquitectura del código

### 6.1. Separación en módulos

```
des_tables      ── solo datos, sin una línea de lógica
     ▲
     ├── des_keyschedule   clave  → 16 subclaves
     ├── des_feistel       f(R,K) → 32 bits
     └── des               IP → 16 rondas → IP⁻¹   (API pública)
              ▲
              └── des_modes          ECB / CBC   (pendiente)
```

Las dependencias fluyen en **una sola dirección**. Reglas que el proyecto
mantiene de forma estricta:

1. **`des_tables` no contiene lógica.** Las tablas son parte de la
   especificación y no cambian nunca; el código que las consume sí evoluciona.
   Aislarlas permite que cualquier módulo las lea sin heredar comportamiento, y
   hace que un error de transcripción sea localizable en un único archivo.

2. **`des_feistel` no conoce el key schedule.** Recibe la subclave ya derivada
   como un `uint64_t`. Así `des_feistel_f()` es una función pura —mismos
   argumentos, mismo resultado, sin estado ni efectos secundarios— trivial de
   testear de forma aislada.

3. **`des.c` nunca incluye `des_modes.h`.** Esta es la regla más importante del
   proyecto y la que justifica toda la estructura.

### 6.2. Por qué la primitiva está separada de los modos

Es una distinción real del diseño criptográfico, no una preferencia estética:

- **La primitiva de bloque** (`des_encrypt_block`) es una permutación
  determinista sobre 64 bits. No tiene estado, no tiene padding, no tiene
  vector de inicialización. Está completamente definida por FIPS 46-3.
- **El modo de operación** (ECB, CBC, CTR…) decide cómo se aplica esa
  primitiva a un mensaje de longitud arbitraria: cómo se rellena el último
  bloque, si hay encadenamiento, si hace falta un IV, cómo se maneja el estado
  entre bloques. Los modos están definidos en documentos aparte
  (SP 800-38A) y son **independientes del cifrador**: el mismo CBC funciona
  sobre DES, AES o cualquier otro cifrador por bloques.

Mezclar ambas capas es una de las causas clásicas de vulnerabilidades reales
(padding oracles, reutilización de IV, ECB aplicado sin advertencia). Al
mantenerlas separadas:

- El núcleo se puede validar contra los vectores oficiales sin que ningún
  detalle de padding o encadenamiento interfiera.
- Añadir ECB, CBC o CTR **no requiere tocar ni una línea** de `des.c`,
  `des_feistel.c` o `des_keyschedule.c`.
- La superficie de riesgo (padding, IVs, manejo de buffers de longitud
  variable) queda confinada en un módulo que se puede revisar por separado.

`include/des_modes.h` y `src/des_modes.c` existen ya, vacíos y con la nota
"próximamente", precisamente para fijar esa frontera desde el primer commit.
`src/des_modes.c` está deliberadamente **fuera del build** (ver `LIB_SRCS` en
el `Makefile`): una unidad de traducción sin declaraciones es un error bajo
`-Wpedantic`.

### 6.3. Convenciones de tipos

Todo el código usa tipos de anchura fija de `<stdint.h>`:

- `uint64_t` para bloques, claves y subclaves.
- `uint32_t` para las mitades `L`/`R` y para los registros `C`/`D` de 28 bits
  (con máscara explícita, ya que no existe un `uint28_t`).
- `uint8_t` para las entradas de las tablas.

Nunca se usan `int`, `long` ni `unsigned` para valores criptográficos: su
anchura depende de la plataforma y un desbordamiento silencioso en un
desplazamiento de bits produciría un cifrado incorrecto pero aparentemente
funcional.

Los bloques se tratan como enteros de 64 bits en los que **el bit 1 del
estándar es el bit más significativo**. Por eso las tablas se almacenan tal
cual aparecen en FIPS 46-3 (1-based) y la conversión a desplazamiento se hace
en un único punto: `(in_bits - table[i])`.

### 6.4. Una decisión discutible: el helper `permute`

La función `permute()` está duplicada como `static` en `des_keyschedule.c`,
`des_feistel.c`, `des.c` y en la suite de pruebas. Es una decisión consciente y
conviene justificarla, porque un revisor la señalará:

- **A favor:** cada módulo queda sin dependencias de los internos de otro, la
  estructura de archivos se mantiene exactamente como se especificó, y el
  helper son cinco líneas sin lógica de negocio. La copia del test, además, es
  deseable: un test no debería validar las tablas usando el mismo código que
  pretende verificar.
- **En contra:** es duplicación real; si se corrigiese un bug en una copia
  habría que replicarlo en las demás.

Si el proyecto crece (más cifradores, más modos), el paso natural es promover
el helper a una cabecera interna `src/des_internal.h`, no exportarlo en la API
pública.

### 6.5. Higiene con material de clave

`des.c` borra el array de subclaves con `secure_zero()` antes de retornar, una
escritura byte a byte a través de un puntero `volatile`. Un `memset` normal
puede ser eliminado por el compilador cuando demuestra que el buffer no se
vuelve a leer (*dead store elimination*), un fallo documentado en código
criptográfico real.

No es una defensa completa —los valores pueden haber quedado en registros o
haberse escrito en swap— y esta implementación **no ofrece garantías de tiempo
constante**: los accesos a las S-boxes dependen de los datos y son, en
principio, vulnerables a ataques de caché. Se documenta explícitamente en lugar
de dar una falsa sensación de seguridad.

---

## 7. Estrategia de pruebas

`tests/test_des.c` valida cuatro niveles, de menor a mayor abstracción:

1. **Consistencia de las tablas.** `IP` e `IP_INV` son permutaciones y una
   deshace a la otra; `E`, `PC-1` y `PC-2` solo indexan bits válidos. Un error
   de transcripción produciría un cifrado reversible pero incompatible con el
   estándar: detectarlo aquí lo localiza en el dato, no 16 rondas después.
2. **Key schedule.** K1 y K16 contra los valores intermedios publicados en
   FIPS 46-3, y comprobación de que alterar los bits de paridad no cambia
   ninguna subclave (es decir: la clave efectiva es de 56 bits).
3. **Vectores conocidos.** El vector oficial más dos casos límite (clave y
   bloque todo ceros / todo unos), verificando cifrado **y** descifrado.
4. **Propiedades algebraicas.** `decrypt(encrypt(x)) == x` sobre 1000 pares
   pseudoaleatorios deterministas, y efecto avalancha: cambiar un solo bit del
   texto claro debe alterar en torno a la mitad de los bits del criptograma.

No se usa ningún framework externo: el proyecto compila y se prueba con un
compilador de C11 y `make`, sin dependencias.

---

## 8. Trabajo pendiente

- Modos de operación ECB y CBC en `des_modes.c`, con padding PKCS#7 y
  verificación estricta al desempaquetar.
- API orientada a buffers (`const uint8_t *` en lugar de `uint64_t`) para
  mensajes de longitud arbitraria.
- Detección de claves débiles y semidébiles (las 4 claves débiles hacen que
  `E_k(E_k(x)) == x`).
- Triple DES (EDE) como extensión histórica natural.

---

## 9. Referencias

- **FIPS PUB 46-3**, *Data Encryption Standard (DES)*, NIST, 1999.
  Especificación normativa; incluye el ejemplo con la clave `133457799BBCDFF1`.
- **FIPS PUB 74**, *Guidelines for Implementing and Using the NBS Data
  Encryption Standard*, 1981.
- **NIST SP 800-38A**, *Recommendation for Block Cipher Modes of Operation*,
  2001. Define ECB, CBC, CFB, OFB y CTR.
- **NIST SP 800-131A Rev. 2**: retirada formal de DES y transición a AES.
- Biham, E. y Shamir, A., *Differential Cryptanalysis of DES-like
  Cryptosystems*, CRYPTO '90.
- Electronic Frontier Foundation, *Cracking DES*, O'Reilly, 1998.
