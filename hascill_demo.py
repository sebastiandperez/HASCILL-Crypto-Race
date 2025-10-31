#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# HASCILL — Crypto Race — Implementación de referencia (educativa)
# © 2025 Sebastián Dario Pérez Pantoja — MIT (ver LICENSE) — SPDX-License-Identifier: MIT
# Si reutilizas, conserva esta línea de atribución.

"""
hascill_demo.py — Demo interactiva de HASCILL (SPN) con n=4 y 10 rondas por defecto.
- Cifrado/descifrado con trazas paso a paso.
- Deriva todo desde la contraseña ASCII:
  m primo, subclaves por ronda (M_r, b_r), IV único y tweaks por bloque/ronda.
- Salidas: bloques, formato CLI y Base64 compacto (2 bytes por entero).

Ejemplos:
    python3 hascill_demo.py --mode enc --password PAZ9 --message Hils
    python3 hascill_demo.py --mode dec --password PAZ9 --cipher "...,..." --n 4 --rounds 10
    python3 hascill_demo.py --mode dec --password PAZ9 --cipher-b64 "AAAA..." --n 4 --rounds 10
"""

import argparse, base64
from typing import List, Tuple

# ========= utilidades de impresión =========

def hrule(ch="=", n=70):
    print(ch * n)

def print_vec(name: str, v: List[int]):
    print(f"{name}: [" + ", ".join(str(x) for x in v) + "]")

def print_mat(name: str, M: List[List[int]]):
    print(f"{name}:")
    for row in M:
        print("   [" + ", ".join(f"{x:>5}" for x in row) + "]")

def format_blocks_for_cli(blocks: List[List[int]]) -> str:
    """[[a,b,...],[...],...] -> 'a,b,... | ... | ...'"""
    return " | ".join(",".join(str(x) for x in blk) for blk in blocks)

# ========= aritmética modular y matrices =========

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0: return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def inv_int(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1: raise ValueError("No existe inversa modular")
    return x % m

def is_prime(p: int) -> bool:
    if p < 2: return False
    if p % 2 == 0: return p == 2
    i = 3
    while i * i <= p:
        if p % i == 0: return False
        i += 2
    return True

def next_prime_condition(start: int, cond=lambda x: True) -> int:
    p = max(2, start)
    if p % 2 == 0 and p != 2: p += 1
    while True:
        if is_prime(p) and cond(p): return p
        p += 2

def matrix_minor(mat: List[List[int]], i: int, j: int) -> List[List[int]]:
    return [row[:j] + row[j+1:] for r, row in enumerate(mat) if r != i]

def det_mod(mat: List[List[int]], m: int) -> int:
    n = len(mat)
    if n == 1: return mat[0][0] % m
    if n == 2: return (mat[0][0]*mat[1][1] - mat[0][1]*mat[1][0]) % m
    total = 0
    for j in range(n):
        sign = -1 if (j % 2) else 1
        sub = matrix_minor(mat, 0, j)
        total = (total + sign * mat[0][j] * det_mod(sub, m)) % m
    return total % m

def adjugate_mod(mat: List[List[int]], m: int) -> List[List[int]]:
    n = len(mat)
    cof = [[0]*n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            sub = matrix_minor(mat, i, j)
            sign = -1 if ((i+j) % 2) else 1
            cof[i][j] = (sign * det_mod(sub, m)) % m
    return [[cof[j][i] % m for j in range(n)] for i in range(n)]

def mat_vec_mul(M: List[List[int]], v: List[int], m: int) -> List[int]:
    n = len(M)
    out = [0]*n
    for i in range(n):
        s = 0
        for j in range(n):
            s += M[i][j] * v[j]
        out[i] = s % m
    return out

def mat_inverse_mod(M: List[List[int]], m: int) -> List[List[int]]:
    d = det_mod(M, m)
    if d % m == 0: raise ValueError("M no invertible")
    inv_d = inv_int(d, m)
    adj = adjugate_mod(M, m)
    n = len(M)
    return [[(inv_d * adj[i][j]) % m for j in range(n)] for i in range(n)]

# ========= S-box y padding =========

def sbox(x: int, m: int) -> int:
    return pow(x, 3, m)

def sbox_inv(y: int, m: int) -> int:
    e = inv_int(3, m - 1)   # inversa de 3 modulo (m-1)
    return pow(y, e, m)

def pkcs7_pad(data: List[int], block_size: int) -> List[int]:
    pad = block_size - (len(data) % block_size)
    if pad == 0: pad = block_size
    return data + [pad] * pad

def pkcs7_unpad(data: List[int]) -> List[int]:
    if not data: raise ValueError("Padding inválido (vacío)")
    pad = data[-1]
    if pad <= 0 or pad > len(data): raise ValueError("Padding inválido (rango)")
    if any(x != pad for x in data[-pad:]): raise ValueError("Padding inválido (patrón)")
    return data[:-pad]

# ========= Derivación desde contraseña =========

def expand_bytes(seed: bytes, needed: int) -> bytes:
    """Expansor didáctico (NO criptográfico)."""
    out = bytearray(); i = 0
    L = len(seed)
    while len(out) < needed:
        b = seed[i % L]
        mix = ((i * 31) ^ (b << 3)) & 0xFF
        out.append(b ^ mix)
        i += 1
    return bytes(out[:needed])

def derive_prime_from_password(password_bytes: bytes) -> int:
    S = sum(password_bytes)
    seed = 257 + (S % 1000)
    # Necesitamos gcd(3, m-1)=1 para que x^3 mod m sea bijectiva
    return next_prime_condition(seed, cond=lambda p: ((p - 1) % 3 != 0 and p >= 257))

def derive_params(password_bytes: bytes, n: int, m: int, max_attempts: int = 16):
    """Devuelve una M invertible, b, IV (compat r=1)."""
    needed = n*n + n + n
    for attempt in range(max_attempts):
        material = expand_bytes(password_bytes + bytes([attempt]), needed)
        it = iter(material)
        M = [[next(it) % m for _ in range(n)] for __ in range(n)]
        b = [next(it) % m for _ in range(n)]
        IV = [next(it) % m for _ in range(n)]
        if det_mod(M, m) % m != 0:
            return M, b, IV
    raise ValueError("No fue posible derivar M invertible")

def compute_tweak(i: int, n: int, m: int, key_sum: int, r: int | None = None) -> List[int]:
    """Tweak por bloque i y (opcional) por ronda r."""
    return [ (key_sum + (i+1)*(j+1) + (0 if r is None else r)) % m for j in range(n) ]

def derive_round_params(password_bytes: bytes, n: int, m: int, rounds: int, max_attempts: int = 16):
    """Deriva subclaves por ronda: (M_r, b_r) para r=1..rounds y un IV único."""
    M1, b1, IV = derive_params(password_bytes, n, m, max_attempts=max_attempts)
    Ms = [M1]; bs = [b1]
    for r in range(2, rounds+1):
        needed = n*n + n
        for attempt in range(max_attempts):
            # Separación de dominio simple: etiqueta de ronda
            material = expand_bytes(password_bytes + b"|R|" + bytes([r, attempt & 0xFF]), needed)
            it = iter(material)
            M = [[next(it) % m for _ in range(n)] for __ in range(n)]
            b = [next(it) % m for _ in range(n)]
            if det_mod(M, m) % m != 0:
                Ms.append(M); bs.append(b)
                break
        else:
            raise ValueError(f"No fue posible derivar M_{r} invertible")
    return Ms, bs, IV

# ========= Helpers ASCII / bloques / Base64 =========

def ascii_list(s: str) -> List[int]:
    try:
        b = s.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("Solo se permite ASCII (0..127)")
    return list(b)

def list_to_ascii(v: List[int]) -> str:
    try:
        return bytes(v).decode("ascii", errors="strict")
    except Exception:
        return bytes(v).decode("ascii", errors="ignore")

def blocks_of(v: List[int], n: int) -> List[List[int]]:
    return [v[i:i+n] for i in range(0, len(v), n)]

def blocks_to_bytes(blocks: List[List[int]]) -> bytes:
    """Serializa cada entero en 2 bytes big-endian (suficiente para m < 65536)."""
    out = bytearray()
    for blk in blocks:
        for x in blk:
            if x < 0 or x > 0xFFFF:
                raise ValueError("Valor fuera de rango para 2 bytes.")
            out.append((x >> 8) & 0xFF)
            out.append(x & 0xFF)
    return bytes(out)

def bytes_to_blocks(data: bytes, n: int) -> List[List[int]]:
    if len(data) % 2 != 0:
        raise ValueError("Bytes inválidos (longitud impar).")
    vals = []
    for i in range(0, len(data), 2):
        vals.append((data[i] << 8) | data[i+1])
    if len(vals) % n != 0:
        raise ValueError(f"N° de enteros {len(vals)} no múltiplo de n={n}.")
    return [vals[i:i+n] for i in range(0, len(vals), n)]

def blocks_to_b64(blocks: List[List[int]]) -> str:
    return base64.b64encode(blocks_to_bytes(blocks)).decode("ascii")

def b64_to_blocks(b64: str, n: int) -> List[List[int]]:
    data = base64.b64decode(b64.encode("ascii"))
    return bytes_to_blocks(data, n)

# ========= Derivación “todo en uno” =========

def derive_all_from_password(password: str, n: int, rounds: int):
    P = ascii_list(password)
    m = derive_prime_from_password(bytes(P))
    key_sum = sum(P) % m
    Ms, bs, IV = derive_round_params(bytes(P), n, m, rounds=rounds)
    return P, m, key_sum, Ms, bs, IV

# ========= Cifrado / Descifrado con trazas (rondas) =========

def encrypt_verbose(password: str, plaintext: str, n: int = 4, rounds: int = 10) -> List[List[int]]:
    hrule()
    print(f"CIFRADO HASCILL — n={n}, rounds={rounds}")
    hrule("-")

    P, m, key_sum, Ms, bs, IV = derive_all_from_password(password, n, rounds)

    print(f"[1] Contraseña: {password!r} → ASCII: {ascii_list(password)}")
    print(f"[2] Primo m derivado: {m} (gcd(3,m-1)=1 para S-box cúbica)")
    for r, Mr in enumerate(Ms, 1):
        print_mat(f"[3] M_{r} (mod m)", Mr)
        print_vec(f"[3] b_{r}", bs[r-1])
    print_vec("[3] IV", IV)
    print(f"[4] key_sum = sum(P) mod m = {key_sum}")
    hrule("-")

    v_ascii = ascii_list(plaintext)
    v_pad = pkcs7_pad(v_ascii, n)
    print_vec("[5] Plaintext ASCII", v_ascii)
    print_vec("[5] + PKCS#7", v_pad)
    v_blocks = blocks_of(v_pad, n)
    print(f"[5] Bloques n={n}: {len(v_blocks)} → {v_blocks}")
    hrule("-")

    prev = IV[:]
    ciphertext_blocks: List[List[int]] = []
    for i, blk in enumerate(v_blocks):
        print(f"[BLOQUE {i}]")
        t0 = compute_tweak(i, n, m, key_sum, r=None)
        print_vec("  tweak t0", t0)
        print_vec("  prev    ", prev)
        print_vec("  v_i     ", blk)

        # Pre-whitening
        x = [(blk[j] + prev[j] + t0[j]) % m for j in range(n)]
        print_vec("  A0) x = v+prev+t0", x)

        # Rondas r=1..R
        for r in range(1, rounds+1):
            tr = t0 if rounds == 1 else compute_tweak(i, n, m, key_sum, r=r)
            x = [sbox(xx, m) for xx in x]                      # B_r
            print_vec(f"  B{r}) S(x)", x)
            x = mat_vec_mul(Ms[r-1], x, m)                     # C_r
            print_vec(f"  C{r}) M_{r}·x", x)
            x = [(x[j] + bs[r-1][j] + tr[j]) % m for j in range(n)]  # D_r
            print_vec(f"  D{r}) x = x+b_{r}+t_{r}", x)

        c = x
        print_vec("  OUT) c", c)
        hrule(".")
        ciphertext_blocks.append(c)
        prev = c[:]

    cli_str = format_blocks_for_cli(ciphertext_blocks)
    b64_str = blocks_to_b64(ciphertext_blocks)
    print("[OUT] Cipher por bloques:", ciphertext_blocks)
    print(f'[OUT] Cipher (CLI):   {cli_str}')
    print(f'[OUT] Cipher (B64):   {b64_str}')
    print("      Descifrar con los mismos --n y --rounds.")
    hrule()
    return ciphertext_blocks

def decrypt_verbose(password: str, ciphertext_blocks: List[List[int]], n: int = 4, rounds: int = 10) -> str:
    hrule()
    print(f"DESCIFRADO HASCILL — n={n}, rounds={rounds}")
    hrule("-")

    P, m, key_sum, Ms, bs, IV = derive_all_from_password(password, n, rounds)
    Minvs = [mat_inverse_mod(Mr, m) for Mr in Ms]

    print(f"[1] Contraseña: {password!r} → ASCII: {ascii_list(password)}")
    print(f"[2] Primo m derivado: {m}")
    for r, (Mr, Mrinv) in enumerate(zip(Ms, Minvs), 1):
        print_mat(f"[3] M_{r}", Mr)
        print_mat(f"[3] M_{r}^(-1)", Mrinv)
        print_vec(f"[3] b_{r}", bs[r-1])
    print_vec("[3] IV", IV)
    print(f"[4] key_sum = {key_sum}")
    hrule("-")

    prev = IV[:]
    recovered: List[int] = []
    for i, c in enumerate(ciphertext_blocks):
        print(f"[BLOQUE {i} — inverso]")
        t0 = compute_tweak(i, n, m, key_sum, r=None)
        print_vec("  tweak t0", t0)
        print_vec("  prev    ", prev)
        print_vec("  c_i     ", c)

        x = c[:]
        # Rondas inversas R..1
        for r in range(rounds, 0, -1):
            tr = t0 if rounds == 1 else compute_tweak(i, n, m, key_sum, r=r)
            x = [(x[j] - bs[r-1][j] - tr[j]) % m for j in range(n)]   # D_r^{-1}
            print_vec(f"  D{r}⁻¹) x = x - b_{r} - t_{r}", x)
            x = mat_vec_mul(Minvs[r-1], x, m)                         # C_r^{-1}
            print_vec(f"  C{r}⁻¹) x = M_{r}^(-1)·x", x)
            x = [sbox_inv(xx, m) for xx in x]                         # B_r^{-1}
            print_vec(f"  B{r}⁻¹) x = S^{-1}(x)", x)

        # Deshacer pre-whitening
        v = [(x[j] - prev[j] - t0[j]) % m for j in range(n)]
        print_vec("  A0⁻¹) v = x - prev - t0", v)
        hrule(".")
        recovered.extend(v)
        prev = c[:]

    print_vec("[OUT] Con padding", recovered)
    unpadded = pkcs7_unpad(recovered)
    print_vec("[OUT] Sin padding", unpadded)
    text = list_to_ascii(unpadded)
    print(f"[OUT] Texto plano: {text!r}")
    hrule()
    return text

# ========= CLI =========

def parse_cipher_blocks(s: str) -> List[List[int]]:
    parts = [p.strip() for p in s.split("|")]
    blocks = []
    for p in parts:
        if not p: continue
        nums = [int(x.strip()) for x in p.split(",") if x.strip()]
        blocks.append(nums)
    return blocks

def main():
    ap = argparse.ArgumentParser(description="Demo HASCILL (cifrado/descifrado con trazas)")
    ap.add_argument("--mode", choices=["enc", "dec"], help="enc (cifrar) o dec (descifrar)")
    ap.add_argument("--password", help="Contraseña ASCII")
    ap.add_argument("--message", help="Mensaje ASCII (para --mode enc)")
    ap.add_argument("--cipher", help="Ciphertext en bloques: \"a,b,c,d | ...\" (para --mode dec)")
    ap.add_argument("--cipher-b64", help="Ciphertext Base64 compacto (para --mode dec)")
    ap.add_argument("--n", type=int, default=4, help="Tamaño de bloque (default 4)")
    ap.add_argument("--rounds", type=int, default=10, help="Número de rondas (default 10)")
    args = ap.parse_args()

    if args.mode == "enc":
        if not (args.password and args.message):
            print("Faltan --password y --message para cifrar."); return
        encrypt_verbose(args.password, args.message, n=args.n, rounds=args.rounds)

    elif args.mode == "dec":
        if not args.password:
            print("Falta --password."); return
        if args.cipher_b64:
            blocks = b64_to_blocks(args.cipher_b64, n=args.n)
        elif args.cipher:
            blocks = parse_cipher_blocks(args.cipher)
        else:
            print("Debes pasar --cipher o --cipher-b64."); return
        for b in blocks:
            if len(b) != args.n:
                raise ValueError(f"Cada bloque debe tener n={args.n} enteros. Recibido: {b}")
        decrypt_verbose(args.password, blocks, n=args.n, rounds=args.rounds)

    else:
        # Modo interactivo rápido
        print("== HASCILL Demo (interactivo) ==")
        mode = input("Modo [enc/dec]: ").strip().lower()
        n = args.n
        R = args.rounds
        password = input("Contraseña ASCII: ").strip()
        if mode == "enc":
            message = input("Mensaje ASCII: ").strip()
            encrypt_verbose(password, message, n=n, rounds=R)
        else:
            kind = input("¿Cipher en [cli/b64]? ").strip().lower()
            if kind == "b64":
                b64 = input("Cipher (Base64): ").strip()
                blocks = b64_to_blocks(b64, n=n)
            else:
                s = input('Cipher (ej: "1,2,3,4 | 5,6,7,8"): ').strip()
                blocks = parse_cipher_blocks(s)
            for b in blocks:
                if len(b) != n:
                    raise ValueError(f"Cada bloque debe tener n={n} enteros. Recibido: {b}")
            decrypt_verbose(password, blocks, n=n, rounds=R)

if __name__ == "__main__":
    main()
