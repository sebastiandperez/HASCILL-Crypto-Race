#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# HASCILL — Crypto Race — Implementación de referencia (educativa)
# Copyright (c) 2025 Sebastián Dario Pérez Pantoja
# Autor: Sebastián Dario Pérez Pantoja — GitHub: https://github.com/tu-usuario
# Licencia: MIT (ver LICENSE) — SPDX-License-Identifier: MIT
# Si reutilizas, conserva esta línea de atribución.
#
# Archivo: hillplus_async_server.py
# Proyecto: HASCILL (antes Hill+)
# Repo: https://github.com/tu-usuario/hascill

import asyncio, json, struct, time, argparse, logging, shlex
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, List
from collections import deque

from game_core import (
    GameState, initial_state, next_step, validate_step
)

HOST, PORT = "0.0.0.0", 5050
MAX_TEAMS = 6
N = 2
PROTO_VER = 1
HEARTBEAT_SEC = 20
RATE_LIMIT_WINDOW = 2.0
RATE_LIMIT_MAX = 6

# ===== framing =====
async def send_json(w: asyncio.StreamWriter, obj: dict):
    try:
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        w.write(struct.pack(">I", len(data)) + data)
        await w.drain()
    except Exception:
        pass

async def recv_json(r: asyncio.StreamReader):
    try:
        hdr = await r.readexactly(4)
        (ln,) = struct.unpack(">I", hdr)
        if ln <= 0 or ln > 1_000_000: return None
        data = await r.readexactly(ln)
        return json.loads(data.decode("utf-8"))
    except asyncio.IncompleteReadError:
        return None
    except Exception:
        return None

# ===== server state =====
@dataclass
class ClientConn:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    last_steps: deque = field(default_factory=lambda: deque(maxlen=32))

@dataclass
class TeamSrvState:
    team_id: int
    conns: Dict[int, ClientConn] = field(default_factory=dict)
    ready: set = field(default_factory=set)
    turn_order: deque = field(default_factory=deque)  # client_ids
    game: Optional[GameState] = None
    started_at: Optional[float] = None
    win_time: Optional[float] = None

    def current_player(self) -> Optional[int]:
        return self.turn_order[0] if self.turn_order else None

    def rotate_phase(self):
        if self.turn_order:
            self.turn_order.rotate(-1)

    def rotate_block(self):
        if self.turn_order:
            self.turn_order.rotate(-1)

class HillServer:
    def __init__(self, password: str, message: str, rotate: str):
        assert rotate in ("phase","block")
        self.password = password
        self.message  = message
        self.rotate   = rotate

        self.teams: Dict[int, TeamSrvState] = {}
        self.next_client_id = 0

        self.start_flag = False
        self.start_time: Optional[float] = None
        self.winner_team: Optional[int] = None
        self.game_over = False
        self.paused = False

        self.lock = asyncio.Lock()
        self._hb_task: Optional[asyncio.Task] = None

        logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

    # ------- util broadcast -------
    async def broadcast_team(self, ts: TeamSrvState, obj: dict):
        for cc in list(ts.conns.values()):
            await send_json(cc.writer, obj)

    async def broadcast_all(self, obj: dict):
        for ts in self.teams.values():
            for cc in list(ts.conns.values()):
                await send_json(cc.writer, obj)

    async def get_team(self, tid: int) -> TeamSrvState:
        async with self.lock:
            if tid not in self.teams:
                ts = TeamSrvState(team_id=tid)
                self.teams[tid] = ts
            return self.teams[tid]

    async def send_turn_status(self, ts: TeamSrvState):
        cur = ts.current_player()
        for cid, cc in ts.conns.items():
            await send_json(cc.writer, {"type":"turn","current":cur,"you_turn":(cid==cur),"order":list(ts.turn_order)})

    # ------- scoreboard -------
    def build_scoreboard(self) -> List[dict]:
        rows = []
        for tid, ts in self.teams.items():
            g = ts.game
            if g is None:
                rows.append({"team": tid, "finished": False, "blocks_done": 0, "total_blocks": 0,
                             "phase": "N/A", "errors": 0, "time_sec": None})
                continue
            total_blocks = len(g.v_blocks)
            blocks_done = g.current_block if not g.finished else total_blocks
            phase = "DONE" if g.finished else g.current_phase
            elapsed = None
            if g.finished and ts.win_time and self.start_time:
                elapsed = round(ts.win_time - self.start_time, 3)
            rows.append({"team": tid, "finished": g.finished,
                         "blocks_done": blocks_done, "total_blocks": total_blocks,
                         "phase": phase, "errors": g.errors, "time_sec": elapsed})
        def sk(r):
            if r["finished"] and r["time_sec"] is not None:
                return (0, r["time_sec"])
            return (1, -(r["blocks_done"]), r["team"])
        rows.sort(key=sk)
        return rows

    def print_scoreboard(self, rows: List[dict]):
        print("\n====== SCOREBOARD ======")
        if self.winner_team is not None:
            print(f"Ganador: Equipo {self.winner_team}")
        print(f"{'Team':<6}{'Estado':<10}{'Bloques':<10}{'Fase':<8}{'Errores':<8}{'Tiempo(s)':<10}")
        for r in rows:
            estado = "DONE" if r["finished"] else "EN CURSO"
            bloques = f"{r['blocks_done']}/{r['total_blocks']}"
            tiempo = f"{r['time_sec']:.3f}" if r["time_sec"] is not None else "-"
            print(f"{r['team']:<6}{estado:<10}{bloques:<10}{r['phase']:<8}{r['errors']:<8}{tiempo:<10}")
        print("========================\n")

    async def publish_scoreboard(self):
        rows = self.build_scoreboard()
        self.print_scoreboard(rows)
        await self.broadcast_all({"type":"scoreboard","winner": self.winner_team, "rows": rows})

    # ------- heartbeat -------
    async def heartbeat_loop(self):
        while True:
            await asyncio.sleep(HEARTBEAT_SEC)
            await self.broadcast_all({"type":"ping","ts": time.time(), "proto": PROTO_VER})

    # ------- network -------
    async def handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        await send_json(writer, {"type":"hello","proto": PROTO_VER,"msg":"Únete con {'type':'join','team':N} (1..6)"})
        msg = await recv_json(reader)
        if not msg or msg.get("type") != "join":
            await send_json(writer, {"type":"error","msg":"Debes unirte con {'type':'join','team':N}"})
            writer.close(); await writer.wait_closed(); return
        try:
            team_id = int(msg.get("team"))
            assert 1 <= team_id <= MAX_TEAMS
        except Exception:
            await send_json(writer, {"type":"error","msg":f"team debe estar entre 1 y {MAX_TEAMS}"})
            writer.close(); await writer.wait_closed(); return

        ts = await self.get_team(team_id)
        async with self.lock:
            self.next_client_id += 1
            cid = self.next_client_id
            ts.conns[cid] = ClientConn(reader, writer)
            ts.ready.discard(cid)
            if not self.start_flag and cid not in ts.turn_order:
                ts.turn_order.append(cid)
        logging.info(f"Cliente {cid} equipo {team_id} desde {addr}")

        await send_json(writer, {"type":"joined","team":team_id,"your_id":cid,"info":{
            "password": self.password, "message": self.message,
            "note":"Todos marcan READY. Tras START: TPW, TMSG, A, B, C, D. Turnos rotativos.",
            "rotate": self.rotate
        }})
        await self.broadcast_team(ts, {"type":"team_status","team":team_id,
            "connected":len(ts.conns),"ready_count":len(ts.ready),
            "ready_all": len(ts.conns)>0 and len(ts.ready)==len(ts.conns)})
        await send_json(writer, {"type":"task","task":"ready","msg":"Envía {'type':'ready'} cuando TÚ estés listo."})
        await self.send_turn_status(ts)

        if self._hb_task is None:
            self._hb_task = asyncio.create_task(self.heartbeat_loop())

        try:
            while True:
                m = await recv_json(reader)
                if m is None:
                    await self.on_disconnect(team_id, cid)
                    return
                t = m.get("type")

                # rate-limit
                now = time.time()
                cc = ts.conns.get(cid)
                if cc:
                    cc.last_steps.append(now)
                    while cc.last_steps and (now - cc.last_steps[0] > RATE_LIMIT_WINDOW):
                        cc.last_steps.popleft()
                    if t == "step_answer" and len(cc.last_steps) > RATE_LIMIT_MAX:
                        await send_json(cc.writer, {"type":"error","msg":"⏱️ Demasiados intentos. Espera un momento e inténtalo de nuevo."})
                        continue

                if t == "ready":
                    await self.on_ready(team_id, cid)
                elif t == "step_answer":
                    if self.game_over or self.paused:
                        await send_json(ts.conns[cid].writer, {"type":"error","msg":"Partida congelada."})
                        continue
                    await self.on_step_answer(team_id, cid, m)
                elif t == "pong":
                    pass
                else:
                    await send_json(writer, {"type":"hint","msg":"Usa {'type':'ready'} o {'type':'step_answer',...}"})
        except Exception as e:
            logging.error(f"Error con cliente {cid} t{team_id}: {e}")
            await self.on_disconnect(team_id, cid)

    async def on_disconnect(self, team_id: int, cid: int):
        ts = await self.get_team(team_id)
        async with self.lock:
            cc = ts.conns.pop(cid, None)
            ts.ready.discard(cid)
            try:
                if cid in ts.turn_order:
                    ts.turn_order.remove(cid)
            except ValueError:
                pass
        if cc:
            try: cc.writer.close(); await cc.writer.wait_closed()
            except: pass
        await self.broadcast_team(ts, {"type":"team_status","team":team_id,
            "connected":len(ts.conns),"ready_count":len(ts.ready),
            "ready_all": len(ts.conns)>0 and len(ts.ready)==len(ts.conns)})
        await self.send_turn_status(ts)

    async def on_ready(self, team_id: int, cid: int):
        ts = await self.get_team(team_id)
        async with self.lock:
            ts.ready.add(cid)
            ready_all = len(ts.conns)>0 and len(ts.ready) == len(ts.conns)
        logging.info(f"READY equipo {team_id}: {len(ts.ready)}/{len(ts.conns)}")
        await self.broadcast_team(ts, {"type":"team_status","team":team_id,
            "connected":len(ts.conns),"ready_count":len(ts.ready),
            "ready_all": ready_all})
        await self.send_turn_status(ts)

        # start global normal
        await self.maybe_start_global()

    async def maybe_start_global(self):
        async with self.lock:
            if self.start_flag or self.game_over: return
            active = [t for t in self.teams.values() if len(t.conns)>0]
            if not active: return
            all_ready = all(len(t.ready)==len(t.conns) for t in active)
            if all_ready:
                await self._do_start()

    async def _do_start(self, countdown: int = 3):
        # broadcast countdown
        for s in range(countdown, 0, -1):
            await self.broadcast_all({"type":"countdown","seconds":s})
            await asyncio.sleep(1)
        self.start_flag = True
        self.start_time = time.time()
        # inicializar estados de juego
        for t in self.teams.values():
            if len(t.conns) == 0:
                t.game = None
                continue
            t.game = initial_state(self.password, self.message, N)
            t.started_at = time.time()
            t.win_time = None
            # cola de turnos (conectados)
            t.turn_order = deque([cid for cid in t.conns.keys()])
        await self.broadcast_all({"type":"start","msg":"¡Comienza la carrera!"})
        # primer paso para cada equipo
        for t in self.teams.values():
            if t.game is not None:
                await self.send_turn_status(t)
                await self.push_next_task(t)

    async def push_next_task(self, ts: TeamSrvState):
        if self.game_over or self.paused or ts.game is None:
            return
        spec = next_step(ts.game)
        cur = ts.current_player()
        payload = {"type":"step","block":spec.block,"phase":spec.phase,
                   "inputs":spec.inputs,"op":spec.op,"output_name":spec.output_name,
                   "turn_cid":cur}
        for cid, cc in ts.conns.items():
            payload["you_turn"] = (cid == cur)
            await send_json(cc.writer, payload)

    async def on_step_answer(self, team_id: int, cid: int, msg: dict):
        ts = await self.get_team(team_id)
        if ts.game is None: return
        phase = msg.get("phase"); block = msg.get("block"); vec = msg.get("vector")

        # turno
        cur = ts.current_player()
        if cid != cur:
            cc = ts.conns.get(cid)
            if cc:
                await send_json(cc.writer, {"type":"error","msg":"⛔ No es tu turno. Espera tu turno."})
            return

        # aridad esperada
        exp_len = 4 if phase in ("TPW","TMSG") else ts.game.n
        if not (isinstance(vec, list) and len(vec) == exp_len and all(isinstance(x,int) for x in vec)):
            ts.game.errors += 1
            cc = ts.conns.get(cid)
            if cc: await send_json(cc.writer, {"type":"error","msg":f"Vector inválido. Debe ser lista de {exp_len} enteros."})
            await self.push_next_task(ts)  # mismo paso
            return

        ok, err = validate_step(ts.game, phase, vec)

        if ok:
            await self.broadcast_team(ts, {"type":"ok","for": f"{phase}" if block==-1 else f"block{block}_phase{phase}"})
            if ts.game.finished:
                if self.winner_team is None:
                    self.winner_team = ts.team_id
                ts.win_time = time.time()
                self.game_over = True
                await self.publish_scoreboard()
                await self.broadcast_all({"type":"game_over","winner": self.winner_team})
                return

            # rotación
            if self.rotate == "phase":
                ts.rotate_phase()
            else:
                if phase == "D":
                    ts.rotate_block()

            await self.send_turn_status(ts)
            await self.push_next_task(ts)
        else:
            ts.game.errors += 1
            cc = ts.conns.get(cid)
            if cc: await send_json(cc.writer, {"type":"error","msg": err or "Error"})
            await self.push_next_task(ts)  # reintento

    # ========== Poderes de admin ==========
    async def admin_kick(self, team: int, client_id: Optional[int]):
        ts = await self.get_team(team)
        removed = 0
        if client_id is None:
            # kick equipo completo
            for cid, cc in list(ts.conns.items()):
                try: cc.writer.close(); await cc.writer.wait_closed()
                except: pass
                removed += 1
            ts.conns.clear()
            ts.ready.clear()
            ts.turn_order.clear()
        else:
            cc = ts.conns.pop(client_id, None)
            if cc:
                try: cc.writer.close(); await cc.writer.wait_closed()
                except: pass
                ts.ready.discard(client_id)
                try:
                    if client_id in ts.turn_order:
                        ts.turn_order.remove(client_id)
                except ValueError:
                    pass
                removed = 1
        await self.broadcast_team(ts, {"type":"team_status","team":team,
            "connected":len(ts.conns),"ready_count":len(ts.ready),
            "ready_all": len(ts.conns)>0 and len(ts.ready)==len(ts.conns)})
        await self.send_turn_status(ts)
        print(f"[ADMIN] kick: removidos={removed} del equipo {team}")

    async def admin_start_now(self):
        if self.start_flag and not self.game_over:
            print("[ADMIN] Ya estaba iniciado.")
            return
        # limpia banderas de fin o pausa
        self.game_over = False
        self.winner_team = None
        self.paused = False
        # limpiar READIES? Forzamos start con lo que haya conectado
        for t in self.teams.values():
            # prepara lista de turnos
            t.turn_order = deque([cid for cid in t.conns.keys()])
            t.ready = set(t.conns.keys())
        await self._do_start(countdown=2)
        print("[ADMIN] start-now ejecutado.")

    async def admin_set_message(self, msg: str):
        if len(msg) != 4 or any(ord(c) > 127 for c in msg):
            print("[ADMIN] set-message: Debe ser ASCII de 4 chars.")
            return
        self.message = msg
        await self._reset_challenge("Nuevo plaintext cargado. Marquen READY.")
        print(f"[ADMIN] Mensaje actualizado: '{msg}'")

    async def admin_set_password(self, pw: str):
        if len(pw) != 4 or any(ord(c) > 127 for c in pw):
            print("[ADMIN] set-password: Debe ser ASCII de 4 chars.")
            return
        self.password = pw
        await self._reset_challenge("Nueva contraseña cargada. Marquen READY.")
        print(f"[ADMIN] Password actualizado: '{pw}'")

    async def _reset_challenge(self, info_text: str):
        # congelar cualquier partida en curso y reiniciar a “lobby”
        self.game_over = False
        self.paused = False
        self.start_flag = False
        self.start_time = None
        self.winner_team = None
        for t in self.teams.values():
            t.game = None
            t.started_at = None
            t.win_time = None
            # mantener conexiones y turnos actuales
        await self.broadcast_all({"type":"info","msg": info_text})
        # pedir READY nuevamente
        for t in self.teams.values():
            await self.broadcast_team(t, {"type":"team_status","team":t.team_id,
                "connected":len(t.conns),"ready_count":len(t.ready),
                "ready_all": len(t.conns)>0 and len(t.ready)==len(t.conns)})
            for cid, cc in t.conns.items():
                await send_json(cc.writer, {"type":"task","task":"ready","msg":"Se cargó un nuevo reto. Envía {'type':'ready'}"})

    async def admin_pause(self):
        if not self.start_flag or self.game_over:
            print("[ADMIN] No hay partida activa para pausar.")
            return
        self.paused = True
        await self.broadcast_all({"type":"info","msg":"⏸️ Partida pausada por admin"})
        print("[ADMIN] Pausado.")

    async def admin_resume(self):
        if not self.paused:
            print("[ADMIN] No estaba pausado.")
            return
        self.paused = False
        await self.broadcast_all({"type":"info","msg":"▶️ Partida reanudada"})
        # reempuja el paso actual de cada equipo
        for t in self.teams.values():
            await self.push_next_task(t)
        print("[ADMIN] Reanudado.")

    async def admin_reset(self):
        # reinicia partida (mantiene conexiones), vuelve a lobby
        self.game_over = False
        self.paused = False
        self.start_flag = False
        self.start_time = None
        self.winner_team = None
        for t in self.teams.values():
            t.game = None
            t.started_at = None
            t.win_time = None
            t.ready.clear()
            # turn_order se conserva (jugadores conectados)
        await self.broadcast_all({"type":"info","msg":"♻️ Reset de partida. Marquen READY para iniciar."})
        # pedir READY
        for t in self.teams.values():
            await self.broadcast_team(t, {"type":"team_status","team":t.team_id,
                "connected":len(t.conns),"ready_count":len(t.ready),
                "ready_all": len(t.conns)>0 and len(t.ready)==len(t.conns)})
            for cid, cc in t.conns.items():
                await send_json(cc.writer, {"type":"task","task":"ready","msg":"Envía {'type':'ready'} para nueva partida."})
        print("[ADMIN] Reset ejecutado.")

    async def admin_set_rotate(self, mode: str):
        if mode not in ("phase","block"):
            print("[ADMIN] set-rotate: usa phase|block")
            return
        if self.start_flag and not self.game_over:
            print("[ADMIN] set-rotate: no se puede cambiar durante partida. Usa reset.")
            return
        self.rotate = mode
        print(f"[ADMIN] Rotación establecida: {mode}")

    async def admin_status(self):
        print(f"[STATUS] rotate={self.rotate} started={self.start_flag} paused={self.paused} game_over={self.game_over}")
        for tid, ts in self.teams.items():
            conn = len(ts.conns); ready = len(ts.ready)
            cur = ts.current_player()
            st = "N/A"
            blk = "-"
            err = "-"
            if ts.game:
                st = ts.game.current_phase
                blk = f"{ts.game.current_block}/{len(ts.game.v_blocks)}"
                err = ts.game.errors
            print(f"  team {tid}: conectados={conn} ready={ready} turno={cur} fase={st} bloque={blk} errores={err}")

    async def admin_team_info(self, team: int):
        ts = await self.get_team(team)
        print(f"[TEAM {team}] conectados={len(ts.conns)} ready={len(ts.ready)} turno={ts.current_player()}")
        if not ts.game:
            print("  sin juego (en lobby)")
            return
        g = ts.game
        print(f"  fase={g.current_phase} bloque={g.current_block}/{len(g.v_blocks)} errores={g.errors} finished={g.finished}")
        print(f"  m={g.m}")
        print(f"  M={g.M}")
        print(f"  b={g.b}  IV={g.IV}")

    async def admin_broadcast(self, text: str):
        await self.broadcast_all({"type":"info","msg":text})
        print("[ADMIN] broadcast enviado.")

    # ------- READY & START -------
    async def on_ready(self, team_id: int, cid: int):
        ts = await self.get_team(team_id)
        async with self.lock:
            ts.ready.add(cid)
            ready_all = len(ts.conns)>0 and len(ts.ready) == len(ts.conns)
        logging.info(f"READY equipo {team_id}: {len(ts.ready)}/{len(ts.conns)}")
        await self.broadcast_team(ts, {"type":"team_status","team":team_id,
            "connected":len(ts.conns),"ready_count":len(ts.ready),
            "ready_all": ready_all})
        await self.send_turn_status(ts)
        await self.maybe_start_global()

# ======= consola admin (REPL) =======
class AdminConsole:
    HELP = """
Comandos:
  kick <team> [client_id]     Expulsa jugador o equipo completo
  start-now                   Fuerza inicio inmediato (countdown corto)
  set-message <ABCD>          Cambia plaintext (4 ASCII) y resetea a lobby
  set-password <WXYZ>         Cambia password (4 ASCII) y resetea a lobby
  pause | resume              Pausa / reanuda partida activa
  reset                       Reinicia a lobby (conexiones se mantienen)
  set-rotate phase|block      Cambia política de turnos (fuera de partida)
  status                      Estado rápido de todos los equipos
  team-info <team>            Detalle del equipo
  broadcast "texto"           Mensaje a todos
  help                        Esta ayuda
  quit                        Cierra el servidor
"""

    def __init__(self, server: HillServer):
        self.server = server

    async def run(self):
        loop = asyncio.get_running_loop()
        print(self.HELP)
        while True:
            # leer línea sin bloquear el loop
            line = await loop.run_in_executor(None, lambda: input("admin> "))
            if not line:
                continue
            try:
                args = shlex.split(line)
            except ValueError:
                print("Sintaxis inválida.")
                continue
            if not args:
                continue
            cmd, *rest = args

            try:
                if cmd == "help":
                    print(self.HELP)
                elif cmd == "kick":
                    if len(rest) < 1:
                        print("Uso: kick <team> [client_id]")
                        continue
                    team = int(rest[0]); cid = int(rest[1]) if len(rest) >= 2 else None
                    await self.server.admin_kick(team, cid)
                elif cmd == "start-now":
                    await self.server.admin_start_now()
                elif cmd == "set-message":
                    if len(rest) != 1:
                        print("Uso: set-message <ABCD>")
                        continue
                    await self.server.admin_set_message(rest[0])
                elif cmd == "set-password":
                    if len(rest) != 1:
                        print("Uso: set-password <WXYZ>")
                        continue
                    await self.server.admin_set_password(rest[0])
                elif cmd == "pause":
                    await self.server.admin_pause()
                elif cmd == "resume":
                    await self.server.admin_resume()
                elif cmd == "reset":
                    await self.server.admin_reset()
                elif cmd == "set-rotate":
                    if len(rest) != 1:
                        print("Uso: set-rotate phase|block")
                        continue
                    await self.server.admin_set_rotate(rest[0])
                elif cmd == "status":
                    await self.server.admin_status()
                elif cmd == "team-info":
                    if len(rest) != 1:
                        print("Uso: team-info <team>")
                        continue
                    await self.server.admin_team_info(int(rest[0]))
                elif cmd == "broadcast":
                    if len(rest) != 1:
                        print('Uso: broadcast "texto"')
                        continue
                    await self.server.admin_broadcast(rest[0])
                elif cmd == "quit":
                    print("Cerrando...")
                    # mandar scoreboard si hay partida
                    if self.server.start_flag:
                        await self.server.publish_scoreboard()
                    # cerrar conexiones
                    for ts in self.server.teams.values():
                        for cc in list(ts.conns.values()):
                            try: cc.writer.close(); await cc.writer.wait_closed()
                            except: pass
                    # matar proceso
                    raise SystemExit
                else:
                    print("Comando desconocido. Escribe 'help'.")
            except SystemExit:
                raise
            except Exception as e:
                print(f"[ADMIN] Error cmd: {e}")

# ===== entrypoints =====
async def run_server(host: str, port: int, password: str, message: str, rotate: str = "phase"):
    srv = HillServer(password, message, rotate)
    server = await asyncio.start_server(srv.handle_conn, host, port)
    print(f"[SERVER] Escuchando en {host}:{port}")
    print(f"[SERVER] Password='{password}'  Message='{message}'  n={N}  rotate={rotate}")
    # lanzar consola admin
    console = AdminConsole(srv)
    async with server:
        await asyncio.gather(
            server.serve_forever(),
            console.run(),
        )

def main():
    ap = argparse.ArgumentParser(description="Hill+ Server (async + admin REPL)")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--password", required=True)
    ap.add_argument("--message", required=True)
    ap.add_argument("--rotate", choices=["phase","block"], default="phase")
    args = ap.parse_args()
    asyncio.run(run_server(args.host, args.port, args.password, args.message, args.rotate))

if __name__ == "__main__":
    main()
