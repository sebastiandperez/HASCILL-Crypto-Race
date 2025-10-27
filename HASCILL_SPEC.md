# HASCILL — Crypto Race — Especificación y guía detallada

**Autor:** Sebastián Dario Pérez Pantoja — creador y mantenedor del método y del proyecto "HASCILL — Crypto Race".

> Documento de referencia del cifrado **HASCILL** y su implementación didáctica en el proyecto “HASCILL — Crypto Race”.

---

## 1) Objetivo y alcance

**HASCILL** es un cifrado **simétrico por bloques** inspirado en el cifrado de Hill clásico, diseñado con fines **educativos** y de **visualización paso a paso**. No pretende reemplazar cifrados modernos (AES/ChaCha20), pero sí mostrar de forma manipulable:

* Derivación de parámetros a partir de la **contraseña (ASCII)**.
* Un **modo por rondas** con: *pre-suma con vector previo*, *S‑box no lineal*, *transformación lineal matricial*, *offset final con bias y tweak*.
* Un **tweak** dependiente de la posición para evitar repeticiones triviales entre bloques.

> **Nota de seguridad:** HASCILL es una construcción didáctica. Para sistemas reales deben emplearse KDFs y cifrados probados. Ver §12.

---

## 2) Notación

* ( n ): tamaño del bloque en enteros (en el juego, ( n=2 )).
* ( m ): módulo primo del anillo ( \mathbb{Z}_m ).
* ( M \in \mathbb{Z}_m^{n\times n} ): matriz clave invertible módulo ( m ).
* ( b, IV, t_i \in \mathbb{Z}_m^n ): vectores bias, inicialización y tweak del bloque ( i ).
* ( v_i ): vector del bloque de texto plano ( i ) (tras padding y empaquetado).
* Operaciones "+", "*" y potencias se entienden **mod ( m )** y por componente cuando aplica.

---

## 3) Derivación de parámetros desde la contraseña

Se parte de una contraseña ASCII (4 caracteres en el juego). Sea ( P ) la secuencia de bytes.

1. **Módulo primo ( m )**

   * Semilla: ( S = \sum P ).
   * Candidato: ( m \ge 257 ) y ( m \equiv̸ 1 \pmod{3} ).
   * Elegir el **primer primo** ( m\ge 257 ) que cumpla lo anterior.
   * Motivo: asegurar ( \gcd(3, m-1) = 1 ) para que la S‑box cúbica sea invertible (ver §5).

2. **Material de clave pseudoaleatorio**

   * Se expande ( P ) a un buffer de ( n^2 + n + n ) bytes mediante una función simple (*expand_bytes*, didáctica).

3. **Extracción de parámetros**

   * ( M \leftarrow n\times n ) bytes (reducidos mod ( m )).
   * ( b \leftarrow n ) bytes.
   * ( IV \leftarrow n ) bytes.
   * Si ( \det(M) \equiv 0\ (\text{mod } m) ), reintentar con un contador de intento anexo a ( P ) (hasta 16 veces).

4. **Suma de clave**

   * ( \text{key_sum} = (\sum P) \bmod m ).

---

## 4) Empaquetado y padding del mensaje

* Convertir el plaintext ASCII en **lista de enteros** (códigos).
* Aplicar **PKCS#7** sobre enteros para que la longitud sea múltiplo de ( n ).
* Particionar en bloques ( v_0, v_1, \dots \in \mathbb{Z}_m^n ).

---

## 5) Componentes de ronda

1. **Tweak por bloque**
   [ t_i[j] = (\text{key_sum} + (i+1)(j+1)) \bmod m, \quad j=0..n-1 ]
   Evita repetición trivial entre bloques y ata cada bloque a su **posición**.

2. **S‑box cúbica**
   [ S(x) = x^3 \bmod m ]
   Es **permutación** sobre ( \mathbb{Z}_m ) cuando ( \gcd(3, m-1)=1 ) (que garantizamos al elegir ( m )).
   Su inversa es ( S^{-1}(y) = y^{e} \bmod m ), con ( e \equiv 3^{-1} \pmod{m-1} ).

---

## 6) Cifrado por bloque (A→B→C→D)

Para el bloque ( i ):

* **A (pre‑suma)**: ( u = v_i + \text{prev} + t_i ).

  * Donde **prev** es ( IV ) si ( i=0 ) o el **cifrado del bloque anterior** ( c_{i-1} ).
  * Analógico a un CBC con tweak.

* **B (no linealidad)**: ( u' = S(u) ) (por componente).

* **C (mezcla lineal)**: ( w = M,u' ).

* **D (offset final)**: ( c_i = w + b + t_i ).

El ciphertext es la concatenación de ( c_0, c_1, \dots ).

---

## 7) Descifrado por bloque (inversas)

Con los mismos ( m, M, b, IV ) y ( t_i ):

* **D⁻¹**: ( w = c_i - b - t_i ).
* **C⁻¹**: ( u' = M^{-1} w ) (existe por construcción).
* **B⁻¹**: ( u = S^{-1}(u') ) con exponente ( e = 3^{-1} \bmod (m-1) ).
* **A⁻¹**: ( v_i = u - \text{prev} - t_i ).
  Actualizar **prev** (\leftarrow c_i) y continuar.
* Al final, quitar **PKCS#7**.

> **Garantía de invertibilidad**: (i) se impone ( \det(M) \not\equiv 0 ), (ii) la S‑box es permutación al garantizar ( \gcd(3, m-1)=1 ).

---

## 8) Qué aporta respecto a Hill clásico

* Hill clásico es **lineal**: ( c = M v ).
* HASCILL añade **no linealidad (S‑box)**, **estado encadenado** (tipo CBC) y **tweak por bloque**.
* La derivación **automática desde la contraseña ASCII** fija ( m, M, b, IV, t_i ) de forma reproducible.

---

## 9) Ejemplo didáctico (n=2)

Supongamos ( \text{password} = ) "PAZ9" y ( \text{message} = ) "Hils".

1. ASCII:

   * PWD → [80, 65, 90, 57]; MSG → [72, 105, 108, 115].
2. Derivación → se obtiene un primo ( m ), matriz ( M ), vectores ( b, IV ) y ( t_0, t_1, \dots ).
3. Partición (n=2) → bloques ( v_0=[72,105], v_1=[108,115] ).
4. Bloque 0:

   * ( u = v_0 + IV + t_0 ) → ( u' = S(u) ) → ( w = M u' ) → ( c_0 = w + b + t_0 ).
5. Bloque 1: usar **prev = c_0** y repetir.
6. Output = ( c_0 || c_1 ).

En el juego, cada paso se calcula manualmente (o por equipo/turnos) para entender **cómo cambian los vectores**.

---

## 10) Complejidad y cálculo a mano

* Con ( n=2 ) los cálculos son de tamaño manejable: sumas, productos y potencias modulares por componente.
* La S‑box ( x^3 \bmod m ) se computa rápido incluso a mano para valores pequeños; la inversa usa el exponente ( e=3^{-1}\bmod(m-1) ) (que puede precomputarse).
* La multiplicación ( M u' ) (2×2) requiere 4 productos y 2 sumas modulares.

---

## 11) Errores frecuentes (y cómo detectarlos)

* **Longitud del vector**: TPW/TMSG esperan 4 enteros; A..D esperan ( n ).
* **Órdenes de fase**: D no puede ejecutarse sin C, etc.
* **Rango**: todos los valores deben estar en ( 0..m-1 ).
* **Padding**: recordar quitarlo al descifrar.

---

## 12) Consideraciones de seguridad (honestas)

* **KDF débil**: la expansión de bytes es deliberadamente simple para docencia; en producción usar **HKDF/SHA‑256**, **PBKDF2**, **scrypt** o **Argon2**.
* **Estructura visible**: S‑box cúbica y tweak lineal son fáciles de analizar; no hay pruebas de seguridad formales.
* **Integridad**: no incluye MAC/AEAD. Un atacante podría alterar bloques sin ser detectado.
* **Recomendación**: tratar HASCILL como **laboratorio** para entender bloques, no como cifrado de misión crítica.

---

## 13) Interfaz con el juego (resumen)

* El servidor expone **fases** como tareas: TPW, TMSG, A, B, C, D (por bloque).
* La validación compara con el resultado correcto y **no avanza** hasta que el vector sea válido.
* El **tweak** asegura que el vector esperado cambie con el índice de bloque, incluso para mensajes repetidos.

---

## 14) Glosario rápido

* **CBC**: modo en cadena; cada bloque usa el cifrado anterior.
* **S‑box**: caja de sustitución no lineal; aquí ( x \mapsto x^3 ) mod ( m ).
* **Tweak**: variación dependiente del índice/bloque que evita repeticiones estructurales.
* **PKCS#7**: esquema de relleno estándar por longitud.

---

## 15) Licencia

El proyecto se distribuye bajo **MIT License** (ver archivo `LICENSE`).

---

## 16) Autoría y aviso de implementación

La **idea general del cifrado de Hill** es pública y ampliamente conocida. **HASCILL**, tal como está definido en este documento (derivación desde ASCII de la contraseña, selección de primo para S‑box cúbica, tweak posicional, pipeline A→B→C→D y el juego educativo "HASCILL — Crypto Race"), junto con su **implementación de software**, ha sido diseñada y desarrollada por **Sebastián Dario Pérez Pantoja**.

© 2025 Sebastián Dario Pérez Pantoja — GitHub: @sebastiand.perez. Implementación publicada bajo **MIT License** (ver `LICENSE`). Si reutilizas el código o el diseño del juego, por favor conserva la atribución.
