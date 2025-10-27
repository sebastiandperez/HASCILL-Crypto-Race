#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# HASCILL — Crypto Race — Implementación de referencia (educativa)
# Copyright (c) 2025 Sebastián Dario Pérez Pantoja
# Autor: Sebastián Dario Pérez Pantoja — GitHub: https://github.com/tu-usuario
# Licencia: MIT (ver LICENSE) — SPDX-License-Identifier: MIT
# Si reutilizas, conserva esta línea de atribución.
#
# Archivo: hillplus_async_client.py
# Proyecto: HASCILL (antes Hill+)
# Repo: https://github.com/tu-usuario/hascill

import asyncio, json, struct, argparse, time

async def send_json(w, obj):
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    w.write(struct.pack(">I", len(data)) + data)
    await w.drain()

async def recv_json(r):
    try:
        hdr = await r.readexactly(4)
        ln = struct.unpack(">I", hdr)[0]
        data = await r.readexactly(ln)
        return json.loads(data.decode("utf-8"))
    except asyncio.IncompleteReadError:
        return None
    except Exception:
        return None

async def heartbeat_task(writer):
    while True:
        await asyncio.sleep(15)
        try:
            await send_json(writer, {"type":"pong","ts": time.time()})
        except Exception:
            return

async def main():
    ap = argparse.ArgumentParser(description="Hill+ Client (async)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5050)
    ap.add_argument("--team", type=int, required=True)
    args = ap.parse_args()

    reader, writer = await asyncio.open_connection(args.host, args.port)
    print(f"[CLIENT] Conectado a {args.host}:{args.port}")

    hello = await recv_json(reader)
    if hello:
        print(hello.get("msg"), f"(proto={hello.get('proto')})")

    await send_json(writer, {"type":"join","team":args.team})

    my_id = None
    hb = asyncio.create_task(heartbeat_task(writer))
    frozen = False

    while True:
        msg = await recv_json(reader)
        if msg is None:
            print("[CLIENT] Conexión cerrada.")
            hb.cancel()
            return

        t = msg.get("type")

        if t == "joined":
            my_id = msg.get("your_id")
            info = msg.get("info", {})
            print(f"🆔 Tu ID: {my_id} | Rotación: {info.get('rotate','?')}")
            print(f"📝 Password: '{info.get('password')}', Message: '{info.get('message')}'")
            print("ℹ️ ", info.get("note",""))

        elif t == "team_status":
            print(f"📊 [EQUIPO {msg.get('team')}] Conectados: {msg.get('connected')} | ⏳ {msg.get('ready_count')}/{msg.get('connected')} listos")

        elif t == "task" and msg.get("task") == "ready":
            s = input("➤ Escribe 'READY' cuando estés listo: ").strip().lower()
            if s == "ready":
                await send_json(writer, {"type":"ready"})
            else:
                print("   (Escribe exactamente READY)")

        elif t == "turn":
            cur = msg.get("current")
            you = msg.get("you_turn")
            order = msg.get("order", [])
            who = "TÚ" if you else f"Jugador {cur}"
            print(f"🔁 Turno actual: {who} | Orden: {order}")

        elif t == "countdown":
            print(f"⏱️  {msg.get('seconds')}")

        elif t == "start":
            print("🚦 ¡Comienza!")

        elif t == "step":
            if frozen:
                continue
            phase = msg.get("phase"); block = msg.get("block")
            inputs = msg.get("inputs", {})
            you_turn = msg.get("you_turn", False)
            turn_cid = msg.get("turn_cid")
            print(f"[PASO] phase={phase} block={block} (turno de {turn_cid}) -> {msg.get('op')}")
            print(f"       inputs={inputs}")

            if you_turn:
                exp = 4 if phase in ("TPW","TMSG") else 2
                vec_str = input(f"• Tu turno: ingresa vector ({exp} enteros separados por coma): ").strip()
                try:
                    vec = [int(x) for x in vec_str.replace(" ","").split(",") if x!=""]
                except:
                    print("Formato inválido.")
                    continue
                await send_json(writer, {"type":"step_answer","phase":phase,"block":block,"vector":vec})
            else:
                print("   (No es tu turno. Observa y prepárate)")

        elif t == "ok":
            print(f"✅ OK: {msg.get('for')}")

        elif t == "error":
            print(f"❌ ERROR: {msg.get('msg')}")

        elif t == "game_over":
            print(f"🏁 Partida finalizada. Ganador: Equipo {msg.get('winner')}")
            frozen = True

        elif t == "scoreboard":
            print("📋 SCOREBOARD recibido:")
            rows = msg.get("rows", [])
            for r in rows:
                print(r)

        elif t == "ping":
            pass

        else:
            print(f"[CLIENT] Mensaje: {msg}")

if __name__ == "__main__":
    asyncio.run(main())
