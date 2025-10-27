#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# HASCILL — Crypto Race — Implementación de referencia (educativa)
# Copyright (c) 2025 Sebastián Dario Pérez Pantoja
# Autor: Sebastián Dario Pérez Pantoja — GitHub: https://github.com/tu-usuario
# Licencia: MIT (ver LICENSE) — SPDX-License-Identifier: MIT
# Si reutilizas, conserva esta línea de atribución.
#
# Archivo: game_core.py
# Proyecto: HASCILL (antes Hill+)
# Repo: https://github.com/tu-usuario/hascill

from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Any

# ======= Utiles matemáticos =======
def egcd(a, b):
    if b == 0: return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def inv_int(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1: raise ValueError("No hay inversa")
    return x % m

def is_prime(p: int) -> bool:
    if p < 2: return False
    if p % 2 == 0: return p == 2
    i = 3
    while i*i <= p:
        if p % i == 0: return False
        i += 2
    return True

def next_prime_condition(start: int, cond=lambda x: True) -> int:
    p = max(2, start)
    if p % 2 == 0 and p != 2: p += 1
    while True:
        if is_prime(p) and cond(p): return p
        p += 2

def derive_prime_from_password(pw_bytes: bytes) -> int:
    S = sum(pw_bytes)
    seed = 257 + (S % 1000)
    return next_prime_condition(seed, cond=lambda p: ((p-1) % 3 != 0 and p >= 257))

def matrix_minor(mat, i, j):
    return [row[:j] + row[j+1:] for r,row in enumerate(mat) if r != i]

def det_mod(mat, m):
    n = len(mat)
    if n == 1: return mat[0][0] % m
    if n == 2: return (mat[0][0]*mat[1][1] - mat[0][1]*mat[1][0]) % m
    total = 0
    for j in range(n):
        sign = -1 if (j % 2) else 1
        total = (total + sign * mat[0][j] * det_mod(matrix_minor(mat,0,j), m)) % m
    return total % m

def adjugate_mod(mat, m):
    n = len(mat)
    cof = [[0]*n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            cof[i][j] = ((-1) ** (i+j)) * det_mod(matrix_minor(mat,i,j), m)
    return [[cof[j][i] % m for j in range(n)] for i in range(n)]

def mat_vec_mul(M, v, m):
    n = len(M); out = [0]*n
    for i in range(n):
        s = 0
        for j in range(n): s += M[i][j] * v[j]
        out[i] = s % m
    return out

def sbox(x: int, m: int) -> int:
    return pow(x, 3, m)

def pkcs7_pad(data: List[int], block_size: int) -> List[int]:
    pad = block_size - (len(data) % block_size)
    if pad == 0: pad = block_size
    return data + [pad]*pad

def expand_bytes(seed: bytes, needed: int) -> bytes:
    out = bytearray(); i = 0
    while len(out) < needed:
        b = seed[i % len(seed)]
        mix = ((i*31) ^ (b<<3)) & 0xFF
        out.append(b ^ mix); i += 1
    return bytes(out[:needed])

def derive_params_from_password(password: str, n: int) -> Tuple[int, List[List[int]], List[int], List[int], int]:
    pw_bytes = password.encode("ascii")
    m = derive_prime_from_password(pw_bytes)
    need = n*n + n + n
    # Reintentar hasta M invertible
    for att in range(16):
        material = expand_bytes(pw_bytes + bytes([att]), need)
        it = iter(material)
        M = [[next(it) % m for _ in range(n)] for __ in range(n)]
        b = [next(it) % m for _ in range(n)]
        IV= [next(it) % m for _ in range(n)]
        if det_mod(M, m) % m != 0:
            key_sum = sum(pw_bytes) % m
            return m, M, b, IV, key_sum
    raise ValueError("No fue posible derivar M invertible")

def tweak(i: int, n: int, m: int, key_sum: int) -> List[int]:
    return [(key_sum + (i+1)*(j+1)) % m for j in range(n)]

# ======= Estado y API del juego =======
@dataclass
class StepSpec:
    """Definición del paso que toca resolver."""
    block: int
    phase: str     # "TPW","TMSG","A","B","C","D"
    inputs: Dict[str, Any]
    op: str
    output_name: str
    arity: int     # longitud esperada del vector respuesta (4 para TPW/TMSG; n para A..D)

@dataclass
class GameState:
    password: str
    message: str
    n: int
    m: int
    M: List[List[int]]
    b: List[int]
    IV: List[int]
    key_sum: int

    # progreso
    ascii_pw_done: bool = False
    ascii_msg_done: bool = False
    current_block: int = 0
    current_phase: str = "TPW"  # TPW,TMSG,A,B,C,D
    prev_vec: List[int] = field(default_factory=list)
    u: Optional[List[int]] = None
    uprime: Optional[List[int]] = None
    w: Optional[List[int]] = None
    c_blocks: List[List[int]] = field(default_factory=list)
    errors: int = 0
    finished: bool = False

    # Datos derivados del mensaje
    v_blocks: List[List[int]] = field(default_factory=list)
    expected_pwd_ascii: List[int] = field(default_factory=list)
    expected_msg_ascii: List[int] = field(default_factory=list)

def initial_state(password: str, message: str, n: int = 2) -> GameState:
    if len(password) != 4 or len(message) != 4:
        raise ValueError("Password y mensaje deben ser 4 ASCII.")
    try:
        pw_bytes = list(password.encode("ascii"))
        msg_bytes = list(message.encode("ascii"))
    except UnicodeEncodeError:
        raise ValueError("ASCII puro requerido")

    m, M, b, IV, key_sum = derive_params_from_password(password, n)
    padded = pkcs7_pad(msg_bytes, n)
    v_blocks = [padded[i:i+n] for i in range(0, len(padded), n)]
    st = GameState(
        password=password, message=message, n=n, m=m, M=M, b=b, IV=IV, key_sum=key_sum,
        ascii_pw_done=False, ascii_msg_done=False, current_block=0, current_phase="TPW",
        prev_vec=IV[:], v_blocks=v_blocks,
        expected_pwd_ascii=pw_bytes, expected_msg_ascii=msg_bytes
    )
    return st

def next_step(state: GameState) -> StepSpec:
    n, m = state.n, state.m
    i = state.current_block
    if not state.ascii_pw_done:
        return StepSpec(-1, "TPW", {"password_hint": state.password, "len": 4}, "translate_password_to_ascii", "ascii", 4)
    if not state.ascii_msg_done:
        return StepSpec(-1, "TMSG", {"message_hint": state.message, "len": 4}, "translate_plaintext_to_ascii", "ascii", 4)

    if state.finished:
        return StepSpec(i, "DONE", {}, "finished", "", n)

    t_i = tweak(i, n, m, state.key_sum)
    if state.current_phase not in ("A","B","C","D"):
        state.current_phase = "A"

    if state.current_phase == "A":
        return StepSpec(i, "A", {"v": state.v_blocks[i], "prev": state.prev_vec, "t": t_i, "m": m}, "u = (v + prev + t) mod m", "u", n)
    if state.current_phase == "B":
        return StepSpec(i, "B", {"u": state.u, "m": m, "sbox": "x^3 mod m"}, "u_prime = S(u)", "u_prime", n)
    if state.current_phase == "C":
        return StepSpec(i, "C", {"M": state.M, "u_prime": state.uprime, "m": m}, "w = M * u_prime mod m", "w", n)
    # D (+ guard)
    return StepSpec(i, "D", {"w": state.w, "b": state.b, "t": t_i, "m": m}, "c = (w + b + t) mod m", "c", n)

def validate_step(state: GameState, phase: str, vector: List[int]) -> Tuple[bool, Optional[str]]:
    """Valida el vector del usuario y AVANZA estado si ok. Si hay error NO avanza."""
    n, m = state.n, state.m
    i = state.current_block
    try:
        if phase == "TPW":
            if vector == state.expected_pwd_ascii:
                state.ascii_pw_done = True
                return True, None
            state.errors += 1
            return False, f"ASCII password incorrecto. Esperado {state.expected_pwd_ascii}"

        if phase == "TMSG":
            if vector == state.expected_msg_ascii:
                state.ascii_msg_done = True
                state.current_phase = "A"
                return True, None
            state.errors += 1
            return False, f"ASCII mensaje incorrecto. Esperado {state.expected_msg_ascii}"

        # a partir de aquí hay que estar en bloque i
        t_i = tweak(i, n, m, state.key_sum)

        if phase == "A":
            comp = [(state.v_blocks[i][j] + state.prev_vec[j] + t_i[j]) % m for j in range(n)]
            if vector == comp:
                state.u = vector
                state.current_phase = "B"
                return True, None
            state.errors += 1
            return False, f"Incorrecto. Esperado u={comp}"

        if phase == "B":
            if state.u is None:
                state.errors += 1
                return False, "Completa fase A primero."
            comp = [sbox(x, m) for x in state.u]
            if vector == comp:
                state.uprime = vector
                state.current_phase = "C"
                return True, None
            state.errors += 1
            return False, f"Incorrecto. Esperado u_prime={comp}"

        if phase == "C":
            if state.uprime is None:
                state.errors += 1
                return False, "Completa fase B primero."
            comp = mat_vec_mul(state.M, state.uprime, m)
            if vector == comp:
                state.w = vector
                state.current_phase = "D"
                return True, None
            state.errors += 1
            return False, f"Incorrecto. Esperado w={comp}"

        if phase == "D":
            if state.w is None:
                state.errors += 1
                return False, "Completa fase C primero."
            comp = [(state.w[j] + state.b[j] + t_i[j]) % m for j in range(n)]
            if vector == comp:
                state.c_blocks.append(vector)
                state.prev_vec = vector[:]
                state.u = state.uprime = state.w = None
                state.current_phase = "A"
                state.current_block += 1
                if state.current_block >= len(state.v_blocks):
                    state.finished = True
                return True, None
            state.errors += 1
            return False, f"Incorrecto. Esperado c={comp}"

        return False, "Fase desconocida."
    except Exception as e:
        state.errors += 1
        return False, f"Error: {e}"
