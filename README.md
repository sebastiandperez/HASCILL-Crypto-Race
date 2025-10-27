# HASCILL — Crypto Race

Juego educativo en terminal para aprender un cifrado **tipo Hill** extendido con:
- Derivación desde **ASCII** de la contraseña → \(m\) primo, \(M\), \(b\), \(IV\), **tweak** por bloque.
- Rondas por bloque: **A** (pre-suma), **B** (S-box cúbica), **C** (multiplicación por \(M\)), **D** (offset).
- **Multiequipo** (hasta 6), varios clientes por equipo, **turnos** rotativos y **scoreboard**.
- **Consola de admin** integrada (REPL): kick, start-now, set-message, set-password, pause/resume, reset, set-rotate, status, team-info, broadcast.

> **Nota:** Proyecto didáctico; no sustituye cifrados de producción (AES/ChaCha20).

---

## Estructura
```
game_core.py                # Lógica pura (determinista) del cifrado y motor de pasos
hillplus_async_server.py    # Servidor asyncio + consola admin (REPL)
hillplus_async_client.py    # Cliente interactivo (terminal)
integration_test.py         # Pruebas de integración con bots "perfectos"
HASCILL_SPEC.md             # Especificación técnica
LICENSE                     # MIT
```

---

## Requisitos
- Python **3.9+**

---

## Ejecutar

### Servidor
```bash
python3 hillplus_async_server.py --host 0.0.0.0 --port 5050 \
 --password PAZ9 --message Hils --rotate phase
```

### Cliente (uno por jugador)
```bash
python3 hillplus_async_client.py --host 127.0.0.1 --port 5050 --team 1
```

**Inicio de partida**: cuando todos los jugadores conectados de cada equipo envían READY.

**Admin "forzar inicio"**: en la consola del server usa `start-now`.

## Turnos (--rotate)
- **phase**: rota después de cada fase (TPW, TMSG, A, B, C, D).
- **block**: rota después de cada bloque (tras D).

## Consola de Admin (REPL)
Comandos básicos (escribe `help` dentro del server para lista completa):
```bash
kick <team> [client_id]     # Expulsar jugador o equipo entero
start-now                   # Forzar inicio inmediato (countdown corto)
set-message <ABCD>          # Cambiar plaintext (4 ASCII) y volver a lobby
set-password <WXYZ>         # Cambiar password (4 ASCII) y volver a lobby
pause | resume              # Pausar / reanudar partida
reset                       # Reiniciar a lobby (mantiene conexiones)
set-rotate phase|block      # Cambiar política de turnos (fuera de partida)
status                      # Resumen rápido de equipos
team-info <team>            # Detalle de un equipo (fase, bloque, m, M, b, IV)
broadcast "texto"           # Anuncio a todos los clientes
quit                        # Cerrar servidor
```

---

## Test de integración (bots)

**1 equipo × 3 bots:**
```bash
python3 integration_test.py
```

Dentro del archivo hay escenarios para 2 y 6 equipos (3 bots c/u).

---

## ¿Cómo funciona el cifrado? (muy breve)

1) De la contraseña ASCII se derivan \(m\) (primo), \(M\) (invertible mod \(m\)), \(b\), \(IV\) y un **tweak** por bloque.

2) Por bloque \(i\):
   - **A)** \(u=v_i+prev+t_i\)
   - **B)** \(u'=S(u)=u^3 \bmod m\)
   - **C)** \(w=M u'\)
   - **D)** \(c=w+b+t_i\)

   `prev = IV` en el primer bloque; luego `prev = c_{i-1}`.

3) Descifrado invierte D, C, B y A; se quita PKCS#7.

---

## Autoría y licencia

- **Implementación y juego**: Sebastián Dario Pérez Pantoja ([@sebastiand.perez](https://github.com/sebastiandperez)).
- © 2025 — Publicado bajo **MIT License** (ver `LICENSE`).
- La idea general del cifrado de Hill es pública; **HASCILL** (derivación desde ASCII, S-box cúbica, tweak posicional, pipeline A→D y dinámica de juego) es la implementación y diseño de este proyecto.

### Cita sugerida
Sebastián D. Pérez Pantoja. *HASCILL — Crypto Race* (educational Hill-based cipher with tweak and S-box). MIT License, 2025. https://github.com/sebastiandperez/HASCILL-Crypto-Race

---

## Descargo

Proyecto educativo. No incluye KDF robusta ni AEAD. Úsalo para enseñanza, demos y exploración.

Para producción: emplea KDF probadas (Argon2/scrypt) y cifrados modernos (AES-GCM/ChaCha20-Poly1305).
