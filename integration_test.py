#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# HASCILL — Crypto Race — Implementación de referencia (educativa)
# Copyright (c) 2025 Sebastián Dario Pérez Pantoja
# Autor: Sebastián Dario Pérez Pantoja — GitHub: https://github.com/sebastiandperez
# Licencia: MIT (ver LICENSE) — SPDX-License-Identifier: MIT
# Si reutilizas, conserva esta línea de atribución.
#
# Archivo: integration_test.py
# Proyecto: HASCILL
# Repo: https://github.com/sebastiandperez/HASCILL-Crypto-Race

import asyncio, json, struct, socket, random, time
from typing import Optional, Tuple, List

from hascill_async_server import run_server

PASSWORD = "PAZ9"
MESSAGE  = "Hils"
ROTATE   = "phase"   # o "block"

# ===== framing helpers =====
async def send_json(w: asyncio.StreamWriter, obj: dict):
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    w.write(struct.pack(">I", len(data)) + data)
    await w.drain()

async def recv_json(r: asyncio.StreamReader):
    try:
        hdr = await r.readexactly(4)
        ln = struct.unpack(">I", hdr)[0]
        data = await r.readexactly(ln)
        return json.loads(data.decode("utf-8"))
    except asyncio.IncompleteReadError:
        return None
    except Exception:
        return None

def pick_free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

# ======= Bot correcto =======
async def perfect_bot(host: str, port: int, team: int, bot_name: str, done_evt: asyncio.Event):
    """
    Bot que:
    - se une al equipo
    - envía READY
    - ante cada 'step' calcula la respuesta correcta a partir de inputs
    - termina cuando recibe game_over o scoreboard
    """
    reader, writer = await asyncio.open_connection(host, port)

    # hello
    await recv_json(reader)
    # join
    await send_json(writer, {"type":"join","team":team})

    # joined + team_status + ready task
    # Esperamos hasta que nos pidan READY
    while True:
        m = await recv_json(reader)
        if m is None: return
        if m.get("type") == "task" and m.get("task") == "ready":
            break

    # READY
    await send_json(writer, {"type":"ready"})

    frozen = False
    you_turn = False

    # Utilidad para resolver el paso
    def solve_step(step: dict) -> Optional[List[int]]:
        phase = step["phase"]
        inputs = step["inputs"]
        if phase == "TPW":
            pw = inputs["password_hint"]
            return [ord(c) for c in pw]
        if phase == "TMSG":
            msg = inputs["message_hint"]
            return [ord(c) for c in msg]
        if phase == "A":
            v   = inputs["v"]
            prev= inputs["prev"]
            t   = inputs["t"]
            m   = inputs["m"]
            return [ (v[i]+prev[i]+t[i]) % m for i in range(len(v)) ]
        if phase == "B":
            u = inputs["u"]; m = inputs["m"]
            return [ pow(x, 3, m) for x in u ]
        if phase == "C":
            M = inputs["M"]; up = inputs["u_prime"]; m = inputs["m"]
            # M * up mod m
            out = []
            for i in range(len(M)):
                s = 0
                for j in range(len(M)):
                    s += M[i][j] * up[j]
                out.append(s % m)
            return out
        if phase == "D":
            w = inputs["w"]; b = inputs["b"]; t = inputs["t"]; m = inputs["m"]
            return [ (w[i]+b[i]+t[i]) % m for i in range(len(w)) ]
        return None

    while True:
        m = await recv_json(reader)
        if m is None:
            return

        t = m.get("type")

        if t == "step":
            if frozen:
                continue
            you_turn = m.get("you_turn", False)
            if not you_turn:
                continue
            vec = solve_step(m)
            if vec is None:
                # no debería pasar
                continue
            await send_json(writer, {"type":"step_answer","phase":m["phase"],"block":m["block"],"vector":vec})

        elif t == "ok":
            # ignoramos
            pass

        elif t == "error":
            # en principio nunca debería llegar para un bot perfecto
            pass

        elif t == "game_over":
            frozen = True
            # esperamos scoreboard y salimos
            # (no hacemos return aún para asegurar que el scoreboard se capture)
        elif t == "scoreboard":
            # Marcamos done
            done_evt.set()
            return
        # else: team_status, turn, countdown, start, ping...

# ======= Escenarios =======
async def scenario_one_team_three_bots():
    host = "127.0.0.1"
    port = pick_free_port()

    # alzamos server
    server_task = asyncio.create_task(run_server(host, port, PASSWORD, MESSAGE, ROTATE))
    await asyncio.sleep(0.5)  # darle tiempo a arrancar

    # 3 bots en el equipo 1
    done_evt = asyncio.Event()
    bots = [asyncio.create_task(perfect_bot(host, port, 1, f"bot{i+1}", done_evt)) for i in range(3)]

    # timeout de seguridad
    try:
        await asyncio.wait_for(done_evt.wait(), timeout=15.0)
        print("[TEST] OK: 1 equipo, 3 bots terminaron y recibieron scoreboard.")
    except asyncio.TimeoutError:
        print("[TEST] ERROR: timeout esperando scoreboard.")
    finally:
        for b in bots:
            b.cancel()
        server_task.cancel()
        # no esperamos graceful shutdown completo para el test

async def scenario_two_teams_three_bots_each():
    host = "127.0.0.1"
    port = pick_free_port()

    server_task = asyncio.create_task(run_server(host, port, PASSWORD, MESSAGE, ROTATE))
    await asyncio.sleep(0.5)

    done_evt = asyncio.Event()
    bots = []
    for team in (1,2):
        for i in range(3):
            bots.append(asyncio.create_task(perfect_bot(host, port, team, f"t{team}b{i+1}", done_evt)))

    try:
        await asyncio.wait_for(done_evt.wait(), timeout=15.0)
        print("[TEST] OK: 2 equipos con 3 bots c/u — hubo ganador y todos recibieron scoreboard/freeze.")
    except asyncio.TimeoutError:
        print("[TEST] ERROR: timeout esperando scoreboard.")
    finally:
        for b in bots:
            b.cancel()
        server_task.cancel()

async def scenario_six_teams_three_bots_each():
    host = "127.0.0.1"
    port = pick_free_port()

    # Arranca el server con los mismos parámetros que venías usando
    server_task = asyncio.create_task(run_server(host, port, PASSWORD, MESSAGE, ROTATE))
    await asyncio.sleep(0.7)  # un pelín más de margen para 18 conexiones

    done_evt = asyncio.Event()
    bots = []
    for team in range(1, 7):         # equipos 1..6
        for i in range(3):            # 3 bots por equipo
            bots.append(asyncio.create_task(
                perfect_bot(host, port, team, f"t{team}b{i+1}", done_evt)
            ))

    # Con 18 clientes, subimos el timeout de seguridad
    try:
        await asyncio.wait_for(done_evt.wait(), timeout=30.0)
        print("[TEST] OK: 6 equipos × 3 bots — hubo ganador y todos recibieron scoreboard/freeze.")
    except asyncio.TimeoutError:
        print("[TEST] ERROR: timeout esperando scoreboard.")
    finally:
        for b in bots:
            b.cancel()
        server_task.cancel()


# ======= main =======
if __name__ == "__main__":
    # asyncio.run(scenario_one_team_three_bots())
    # Descomenta para correr el escenario de 2 equipos:
    # asyncio.run(scenario_two_teams_three_bots_each())
    asyncio.run(scenario_six_teams_three_bots_each())
