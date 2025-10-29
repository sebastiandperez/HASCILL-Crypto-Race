#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# HASCILL — Crypto Race — Implementación de referencia (educativa)
# © 2025 Sebastián Dario Pérez Pantoja — MIT (ver LICENSE) — SPDX-License-Identifier: MIT
# Si reutilizas, conserva esta línea de atribución.

"""
hascill_demo.py — Demo interactiva de HASCILL con trazas detalladas.

- encrypt_verbose(password, plaintext, n=2): imprime cada paso del cifrado y retorna lista de bloques cifrados.
- decrypt_verbose(password, ciphertext_blocks, n=2): imprime cada paso inverso y retorna el texto plano.

NUEVO:
- Salida adicional en Base64: 'ciphertext ASCII' compacto con --cipher-b64 (usa 2 bytes por entero, big-endian).

Ejemplos:
    python3 hascill_demo.py --mode enc --password PAZ9 --message Hils
    python3 hascill_demo.py --mode dec --password PAZ9 --cipher "417,369 | 101,55"
    python3 hascill_demo.py --mode dec --password PAZ9 --cipher-b64 "AA8xAH..." --n 2
"""

import argparse, base64
from typing import List, Tuple

# ========= utilidades de impresión =========

def hrule(ch="=", n=60):
    print(ch * n)

def print_vec(name: str, v: List[int]):
    print(f"{name}: [{', '.join(str(x) for x in v)}]")

def print_mat(name: str, M: List[List[int]]):
    print(f"{name}:")
    for row in M:
        print("   ", "[" + ", ".join(f"{x:>4}" for x in row) + "]")

def format_blocks_for_cli(blocks: List[List[int]]) -> str:
    """[[a,b],[c,d],...] -> 'a,b | c,d | ...'"""
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
    e = inv_int(3, m - 1)
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
    """Expansor simple (didáctico). Para producción usar KDFs robustas."""
    out = bytearray(); i = 0
    while len(out) < needed:
        b = seed[i % len(seed)]
        mix = ((i * 31) ^ (b << 3)) & 0xFF
        out.append(b ^ mix); i += 1
    return bytes(out[:needed])

def derive_prime_from_password(password_bytes: bytes) -> int:
    S = sum(password_bytes)
    seed = 257 + (S % 1000)
    return next_prime_condition(seed, cond=lambda p: ((p - 1) % 3 != 0 and p >= 257))

def derive_params(password_bytes: bytes, n: int, m: int, max_attempts: int = 16) -> Tuple[List[List[int]], List[int], List[int]]:
    needed = n*n + n + n
    attempt = 0
    while attempt < max_attempts:
        material = expand_bytes(password_bytes + bytes([attempt]), needed)
        it = iter(material)
        M = [[next(it) % m for _ in range(n)] for __ in range(n)]
        b = [next(it) % m for _ in range(n)]
        IV = [next(it) % m for _ in range(n)]
        if det_mod(M, m) % m != 0:
            return M, b, IV
        attempt += 1
    raise ValueError("No fue posible derivar M invertible")

def compute_tweak(i: int, n: int, m: int, key_sum: int) -> List[int]:
    return [(key_sum + (i + 1) * (j + 1)) % m for j in range(n)]

# ========= Helpers ASCII / empaquetado =========

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

# ========= Serialización Base64 (ASCII seguro) =========

def blocks_to_bytes(blocks: List[List[int]]) -> bytes:
    """Serializa [[a,b],[c,d],...] como bytes usando 2 bytes por entero (big-endian)."""
    out = bytearray()
    for blk in blocks:
        for x in blk:
            if x < 0 or x > 0xFFFF:
                raise ValueError("Valor fuera de rango para serialización de 2 bytes.")
            out.append((x >> 8) & 0xFF)
            out.append(x & 0xFF)
    return bytes(out)

def bytes_to_blocks(data: bytes, n: int) -> List[List[int]]:
    """Deserializa bytes (2 bytes por entero) a [[...],[...]] con aridad n."""
    if len(data) % 2 != 0:
        raise ValueError("Bytes inválidos: longitud impar.")
    vals = []
    for i in range(0, len(data), 2):
        vals.append((data[i] << 8) | data[i+1])
    if len(vals) % n != 0:
        raise ValueError(f"Número de enteros {len(vals)} no múltiplo de n={n}.")
    blocks = []
    for i in range(0, len(vals), n):
        blocks.append(vals[i:i+n])
    return blocks

def blocks_to_b64(blocks: List[List[int]]) -> str:
    return base64.b64encode(blocks_to_bytes(blocks)).decode("ascii")

def b64_to_blocks(b64: str, n: int) -> List[List[int]]:
    data = base64.b64decode(b64.encode("ascii"))
    return bytes_to_blocks(data, n)

# ========= Cifrado / Descifrado con trazas =========

def derive_all_from_password(password: str, n: int):
    P = ascii_list(password)
    m = derive_prime_from_password(bytes(P))
    key_sum = sum(P) % m
    M, b, IV = derive_params(bytes(P), n, m)
    return P, m, key_sum, M, b, IV

def encrypt_verbose(password: str, plaintext: str, n: int = 2) -> List[List[int]]:
    hrule()
    print("CIFRADO HASCILL — trazas")
    hrule("-")

    P, m, key_sum, M, b, IV = derive_all_from_password(password, n)

    print(f"[1] Contraseña: {password!r} → ASCII:", ascii_list(password))
    print(f"[1] Mensaje    : {plaintext!r} → ASCII:", ascii_list(plaintext))
    print(f"[2] Primo m derivado: {m}  (garantiza S-box cúbica invertible)")
    print_mat("[3] Matriz M (mod m)", M)
    print_vec("[3] b", b)
    print_vec("[3] IV", IV)
    print(f"[4] key_sum = sum(P) mod m = {key_sum}")
    hrule("-")

    v = ascii_list(plaintext)
    v_pad = pkcs7_pad(v, n)
    print_vec("[5] Plaintext ASCII", v)
    print_vec("[5] + PKCS#7", v_pad)
    v_blocks = blocks_of(v_pad, n)
    print(f"[5] Bloques n={n}: {len(v_blocks)} →", v_blocks)
    hrule("-")

    prev = IV[:]
    ciphertext_blocks: List[List[int]] = []
    for i, blk in enumerate(v_blocks):
        print(f"[BLOQUE {i}]")
        t_i = compute_tweak(i, n, m, key_sum)
        print_vec("  tweak t_i", t_i)
        print_vec("  prev     ", prev)
        print_vec("  v_i      ", blk)

        u = [(blk[j] + prev[j] + t_i[j]) % m for j in range(n)]
        print_vec("  A) u = v+prev+t", u)

        u_prime = [sbox(x, m) for x in u]
        print_vec("  B) u' = S(u)", u_prime)

        w = mat_vec_mul(M, u_prime, m)
        print_vec("  C) w = M·u'", w)

        c = [(w[j] + b[j] + t_i[j]) % m for j in range(n)]
        print_vec("  D) c = w+b+t", c)
        hrule(".")

        ciphertext_blocks.append(c)
        prev = c[:]

    cli_str = format_blocks_for_cli(ciphertext_blocks)
    b64_str = blocks_to_b64(ciphertext_blocks)

    print("[OUT] Cipher por bloques:", ciphertext_blocks)
    print(f'[OUT] Cipher (CLI):   {cli_str}')
    print(f'[OUT] Cipher (B64):   {b64_str}')
    print("      Usa:  --mode dec --password TU_PASS --cipher", f'"{cli_str}"')
    print("         o: --mode dec --password TU_PASS --cipher-b64", f'"{b64_str}"', f"--n {n}")
    hrule()
    return ciphertext_blocks

def decrypt_verbose(password: str, ciphertext_blocks: List[List[int]], n: int = 2) -> str:
    hrule()
    print("DESCIFRADO HASCILL — trazas")
    hrule("-")

    P, m, key_sum, M, b, IV = derive_all_from_password(password, n)
    Minv = mat_inverse_mod(M, m)

    print(f"[1] Contraseña: {password!r} → ASCII:", ascii_list(password))
    print(f"[2] Primo m derivado: {m}")
    print_mat("[3] M", M)
    print_mat("[3] M^{-1}", Minv)
    print_vec("[3] b", b)
    print_vec("[3] IV", IV)
    print(f"[4] key_sum = {key_sum}")
    hrule("-")

    prev = IV[:]
    recovered: List[int] = []
    for i, c in enumerate(ciphertext_blocks):
        print(f"[BLOQUE {i} — inverso]")
        t_i = compute_tweak(i, n, m, key_sum)
        print_vec("  tweak t_i", t_i)
        print_vec("  prev     ", prev)
        print_vec("  c_i      ", c)

        w = [(c[j] - b[j] - t_i[j]) % m for j in range(n)]
        print_vec("  D⁻¹) w = c - b - t", w)

        u_prime = mat_vec_mul(Minv, w, m)
        print_vec("  C⁻¹) u' = M^{-1}·w", u_prime)

        u = [sbox_inv(y, m) for y in u_prime]
        print_vec("  B⁻¹) u = S^{-1}(u')", u)

        v = [(u[j] - prev[j] - t_i[j]) % m for j in range(n)]
        print_vec("  A⁻¹) v = u - prev - t", v)
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
    """Parses 'a,b | c,d | ...' → [[a,b],[c,d],...]"""
    parts = [p.strip() for p in s.split("|")]
    blocks = []
    for p in parts:
        if not p:
            continue
        nums = [int(x.strip()) for x in p.split(",") if x.strip()]
        blocks.append(nums)
    return blocks

def main():
    ap = argparse.ArgumentParser(description="Demo HASCILL (cifrado/descifrado con trazas)")
    ap.add_argument("--mode", choices=["enc", "dec"], help="enc (cifrar) o dec (descifrar)")
    ap.add_argument("--password", help="Contraseña ASCII")
    ap.add_argument("--message", help="Mensaje ASCII (para --mode enc)")
    ap.add_argument("--cipher", help="Ciphertext en bloques: \"a,b | c,d | ...\" (para --mode dec)")
    ap.add_argument("--cipher-b64", help="Ciphertext Base64 compacto (para --mode dec)")
    ap.add_argument("--n", type=int, default=2, help="Tamaño de bloque (por defecto 2)")
    args = ap.parse_args()

    if args.mode == "enc":
        if not (args.password and args.message):
            print("Faltan --password y --message para cifrar.")
            return
        encrypt_verbose(args.password, args.message, n=args.n)

    elif args.mode == "dec":
        if not args.password:
            print("Falta --password.")
            return
        if args.cipher_b64:
            blocks = b64_to_blocks(args.cipher_b64, n=args.n)
        elif args.cipher:
            blocks = parse_cipher_blocks(args.cipher)
        else:
            print("Debes pasar --cipher o --cipher-b64.")
            return
        # validar aridad n
        for b in blocks:
            if len(b) != args.n:
                raise ValueError(f"Cada bloque debe tener n={args.n} enteros. Recibido: {b}")
        decrypt_verbose(args.password, blocks, n=args.n)

    else:
        # modo interactivo
        print("== HASCILL Demo (interactivo) ==")
        mode = input("Modo [enc/dec]: ").strip().lower()
        n = args.n
        if mode not in ("enc", "dec"):
            print("Modo inválido."); return
        password = input("Contraseña ASCII: ").strip()
        if mode == "enc":
            message = input("Mensaje ASCII: ").strip()
            encrypt_verbose(password, message, n=n)
        else:
            kind = input("¿Cipher en [cli/b64]? ").strip().lower()
            if kind == "b64":
                b64 = input("Cipher (Base64): ").strip()
                blocks = b64_to_blocks(b64, n=n)
            else:
                s = input('Cipher (ej: "417,369 | 101,55"): ').strip()
                blocks = parse_cipher_blocks(s)
            for b in blocks:
                if len(b) != n:
                    raise ValueError(f"Cada bloque debe tener n={n} enteros. Recibido: {b}")
            decrypt_verbose(password, blocks, n=n)

if __name__ == "__main__":
    main()
