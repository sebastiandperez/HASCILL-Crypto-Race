# HASCILL — Crypto Race — Especificación y guía detallada

**Autor:** Sebastián Dario Pérez Pantoja — creador y mantenedor del método y del proyecto "HASCILL — Crypto Race".

> Documento de referencia del cifrado **HASCILL** y su implementación didáctica en el proyecto “HASCILL — Crypto Race”.

---

## 1) Objetivo y alcance

**HASCILL** es un cifrado **simétrico por bloques** inspirado en el cifrado de Hill clásico, diseñado con fines **educativos** y de **visualización paso a paso**. No pretende reemplazar cifrados modernos (AES/ChaCha20), pero sí mostrar de forma manipulable:

- Derivación de parámetros a partir de la **contraseña (ASCII)**.
- Un **modo por rondas**: *pre-suma con vector previo (pre-whitening)*, *S-box no lineal*, *transformación lineal matricial*, *offset con bias y tweak*, repetidos **R** veces.
- Un **tweak** dependiente de la posición (y de la ronda) para evitar repeticiones triviales entre bloques.

> **Configuración base del proyecto:** **tamaño de bloque n = 4** y **número de rondas R = 10**.
> (Se puede ajustar para fines didácticos; la demo y el juego soportan otros valores, aún así, este cifrado fue planteado para ejecutarse bajo esos parametros.)

> **Nota de seguridad:** HASCILL es una construcción didáctica. Para sistemas reales deben emplearse KDFs y cifrados probados. Ver §12.

---

## 2) Notación

- **n**: tamaño del bloque en enteros y dimensión de la matriz (configuración base **n = 4**).
- **R**: número de rondas del cifrado (configuración base **R = 10**).
- **m**: módulo primo del anillo \( \mathbb{Z}_m \).
- \( M_r \in \mathbb{Z}_m^{n\times n} \): matriz de la **ronda r** (invertible módulo \(m\)).
- \( b_r, IV, t_{i,r} \in \mathbb{Z}_m^n \): bias por ronda \(b_r\), vector de inicialización \(IV\) y tweak del bloque \(i\) en la ronda \(r\).
- \( v_i \): bloque de texto plano (tras padding).
- Todas las operaciones son **mod \(m\)**; S-box y sumas por componente.

---

## 3) Derivación de parámetros desde la contraseña

Se parte de una contraseña ASCII. Sea \( P \) la secuencia de bytes.

1. **Módulo primo \(m\)**
   Semilla \( S = \sum P \). Elegir el **primer primo \(m \ge 257\)** tal que \( (m-1) \not\equiv 0 \ (\bmod\ 3) \).
   Motivo: asegurar \( \gcd(3, m-1)=1 \) para que la S-box cúbica sea invertible.

2. **Material pseudoaleatorio didáctico**
   Se expande \(P\) con un expansor simple (*expand_bytes*) para obtener bytes suficientes.

3. **Subclaves por ronda**
   - Para **r = 1..R** se derivan \( M_r \) (invertible mod \(m\)) y \( b_r \) con **separación de dominio por ronda** (etiqueta de ronda en el expansor).
   - Se deriva un **IV** único para todo el mensaje. Si \( \det(M_r) \equiv 0 \), se reintenta (hasta 16).

4. **Suma de clave**
   \( \text{key\_sum} = (\sum P) \bmod m \).

---

## 4) Empaquetado y padding del mensaje

- Convertir el plaintext ASCII en **lista de enteros** (códigos).
- Aplicar **PKCS#7** para que la longitud sea múltiplo de \( n \).
- Particionar en bloques \( v_0, v_1, \dots \in \mathbb{Z}_m^n \).

---

## 5) Componentes de ronda

1. **Tweak por bloque y ronda**
   \( t_{i,r}[j] = \big(\text{key\_sum} + (i+1)(j+1) + r\big) \bmod m,\ \ j=0..n-1 \).
   (Para compatibilidad 1 ronda puede usarse \(t_{i,0}\) en el pre-whitening.)

2. **S-box cúbica**
   \( S(x) = x^3 \bmod m \), permutación sobre \( \mathbb{Z}_m \) con \( \gcd(3, m-1)=1 \).
   Inversa: \( S^{-1}(y) = y^e \bmod m \), con \( e \equiv 3^{-1} \ (\bmod\ m-1) \).

---

## 6) Cifrado por bloque (pre-whitening + **R** rondas)

Para el bloque \( i \) (con **prev** = \(IV\) si \(i=0\) o \(c_{i-1}\) si \(i>0\)):

1) **Pre-whitening (A0)**
\( x_0 = v_i + \text{prev} + t_{i,0} \)  — usa tweak base del bloque; depende de \(i\), no de \(r\).

2) **Rondas \( r = 1..R \)**
Para cada \(r\):
- **B\(_r\)** (no linealidad): \( x \leftarrow S(x) \)
- **C\(_r\)** (mezcla lineal): \( x \leftarrow M_r \cdot x \)
- **D\(_r\)** (offset): \( x \leftarrow x + b_r + t_{i,r} \)

3) **Salida**
\( c_i = x \). Actualizar **prev = c_i** (encadenamiento tipo CBC con tweak).

> La configuración base aplica **R = 10** rondas.

---

## 7) Descifrado por bloque (inversas en orden inverso)

Con los mismos \( m, M_r, b_r, IV \) y \( t_{i,r} \):

1) \( x \leftarrow c_i \)
2) Para \( r = R..1 \):
   - **D\(_r^{-1}\)**: \( x \leftarrow x - b_r - t_{i,r} \)
   - **C\(_r^{-1}\)**: \( x \leftarrow M_r^{-1} \cdot x \)
   - **B\(_r^{-1}\)**: \( x \leftarrow S^{-1}(x) \)
3) **A0\(^{-1}\)**: \( v_i = x - \text{prev} - t_{i,0} \)
   Actualizar **prev = c_i**.
4) Quitar **PKCS#7** al final.

> **Invertibilidad garantizada:** (i) \( \det(M_r)\not\equiv 0 \), (ii) S-box es permutación, (iii) sumas modulares son reversibles.

---

## 8) Qué aporta respecto a Hill clásico

- Hill clásico: **lineal** \( c = M v \) (y, en variantes, \( c = M v + b \)).
- HASCILL (base **n=4, R=10**): añade **no linealidad** (S-box), **encadenamiento** por bloque, **tweak por bloque y ronda**, **múltiples rondas** con subclaves distintas, y **pre-whitening**.
- Deriva **m, \(M_r\), \(b_r\), \(IV\), \(t_{i,r}\)** **desde la contraseña ASCII** de forma reproducible.

---

## 9) Ejemplo didáctico

Para exposición manual en clase puede usarse **n=2** y **R=1–3** (más corto de calcular a mano).
Para la **demo base** del proyecto se usa **n=4** y **R=10** (mayor difusión y dificultad).

---

## 10) Complejidad y cálculo a mano

- Con **n=4, R=10** hay 1 pre-suma + \(3R\) pasos por bloque (S-box, mezcla, offset).
- Para práctica manual, reducir a **n=2** y **R=1–3** resulta manejable; la S-box \(x^3 \bmod m\) y su inversa son rápidas con exponentiación modular.

---

## 11) Errores frecuentes (y cómo detectarlos)

- **Longitud del bloque**: Asegurar vectores de tamaño \(n\).
- **Orden de fases**: invertir exactamente en orden inverso.
- **Rangos**: todos los valores en \(0..m-1\).
- **Padding**: usar y retirar **PKCS#7** correctamente.
- **Parámetros**: cifrar y descifrar deben usar **mismo \(n\)** y **mismo R**.

---

## 12) Consideraciones de seguridad (honestas)

- **KDF débil (docente)**: el expansor es intencionalmente simple; en producción usar **Argon2id/scrypt/HKDF**.
- **Estructura visible**: S-box cúbica y capas lineales con tweaks lineales facilitan análisis con suficientes datos.
- **Integridad ausente**: no hay MAC/AEAD.
- **Consejo**: tratar HASCILL como **laboratorio** conceptual. Para protección real: AEAD moderno.

---

## 13) Interfaz con el juego (resumen)

- El servidor presenta **fases** por bloque y ronda (TPW/TMSG para traducciones, luego A0, y ciclos B/C/D por ronda).
- La validación no avanza si el vector es incorrecto.
- El **tweak** hace que los resultados esperados cambien con la **posición del bloque** y la **ronda**.

---

## 14) Glosario rápido

- **CBC**: encadenamiento por bloque (usa el resultado previo).
- **S-box**: sustitución no lineal; aquí \( x \mapsto x^3 \bmod m \).
- **Tweak**: variación dependiente de índice/ronda que evita repeticiones.
- **PKCS#7**: padding estándar.

---

## 15) Licencia

El proyecto se distribuye bajo **MIT License** (ver archivo `LICENSE`).

---

## 16) Autoría y aviso de implementación

La **idea general del cifrado de Hill** es pública y ampliamente conocida. **HASCILL**, tal como está definido en este documento (derivación desde ASCII de la contraseña, selección de primo para S-box cúbica, **pipeline por rondas** con **configuración base n=4 y R=10**, tweak posicional por bloque y ronda, y el juego educativo "HASCILL — Crypto Race"), junto con su **implementación de software**, ha sido diseñada y desarrollada por **Sebastián Dario Pérez Pantoja**.

© 2025 Sebastián Dario Pérez Pantoja — GitHub: @sebastiand.perez. Implementación publicada bajo **MIT License** (ver `LICENSE`). Si reutilizas el código o el diseño del juego, por favor conserva la atribución.
