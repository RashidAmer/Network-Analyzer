"""
app.py — FastAPI backend for network-analyzer.

Starts the C sniffer as a subprocess, reads its JSON stdout line-by-line,
stores packets + stats in SQLite, and exposes a REST + WebSocket API.

Run locally (without Docker):
    sudo INTERFACE=eth0 uvicorn app:app --reload --port 8000
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import aiosqlite
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from database import (
    init_db, get_db, DB_PATH,
    insert_packet, insert_stats,
    query_metrics, query_flows, query_top_talkers,
    query_recent_packets, query_timeseries, query_latest_stats,
)

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────
INTERFACE      = os.getenv("INTERFACE", "any")
FLUSH_INTERVAL = int(os.getenv("FLUSH_INTERVAL", "5"))
ROLLING_WINDOW = int(os.getenv("ROLLING_WINDOW", "10"))
SNIFFER_PATH   = Path(__file__).parent.parent / "c" / "sniffer"
# Inside Docker the sniffer is at /app/sniffer
if not SNIFFER_PATH.exists():
    SNIFFER_PATH = Path("/app/sniffer")

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("network-analyzer")

# ── WebSocket connection manager ──────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)

manager = ConnectionManager()

# ── Sniffer subprocess management ────────────────────────────────────────
sniffer_proc: Optional[subprocess.Popen] = None
sniffer_task: Optional[asyncio.Task]     = None
sniffer_ready = asyncio.Event()


async def read_sniffer_output(proc: subprocess.Popen):
    """
    Reads JSON lines from the sniffer stdout.
    Inserts packet records into SQLite and broadcasts to WebSocket clients.
    """
    global sniffer_ready
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA synchronous=NORMAL")

    try:
        loop = asyncio.get_event_loop()
        while True:
            line = await loop.run_in_executor(None, proc.stdout.readline)
            if not line:
                break
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                log.warning("Bad JSON from sniffer: %s", line[:120])
                continue

            msg_type = data.get("type")

            if msg_type == "ready":
                log.info("Sniffer ready on interface: %s",
                         data.get("interface"))
                sniffer_ready.set()

            elif msg_type == "packet":
                await insert_packet(db, data)
                await db.commit()
                await manager.broadcast(data)

            elif msg_type == "stats":
                await insert_stats(db, data)
                await db.commit()
                await manager.broadcast(data)

            elif msg_type == "error":
                log.error("Sniffer error: %s", data.get("msg"))

            elif msg_type == "shutdown":
                log.info("Sniffer shut down cleanly.")
                break

    except Exception as exc:
        log.exception("Sniffer reader crashed: %s", exc)
    finally:
        await db.close()


async def start_sniffer():
    global sniffer_proc, sniffer_task, sniffer_ready

    if not SNIFFER_PATH.exists():
        log.error("Sniffer binary not found at %s — did you compile it?",
                  SNIFFER_PATH)
        return

    log.info("Starting sniffer on interface '%s'", INTERFACE)
    sniffer_ready.clear()

    sniffer_proc = subprocess.Popen(
        [str(SNIFFER_PATH), INTERFACE,
         str(FLUSH_INTERVAL), str(ROLLING_WINDOW)],
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )

    sniffer_task = asyncio.create_task(
        read_sniffer_output(sniffer_proc),
        name="sniffer-reader",
    )


async def stop_sniffer():
    global sniffer_proc, sniffer_task
    if sniffer_proc and sniffer_proc.poll() is None:
        sniffer_proc.terminate()
        try:
            sniffer_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            sniffer_proc.kill()
    if sniffer_task:
        sniffer_task.cancel()


async def watchdog():
    """Restart the sniffer if it crashes."""
    while True:
        await asyncio.sleep(5)
        if sniffer_proc and sniffer_proc.poll() is not None:
            log.warning("Sniffer exited (code %d) — restarting …",
                        sniffer_proc.returncode)
            await start_sniffer()


# ── App lifecycle ─────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await start_sniffer()
    asyncio.create_task(watchdog(), name="sniffer-watchdog")
    yield
    await stop_sniffer()


app = FastAPI(
    title="Network Analyzer API",
    version="1.0.0",
    description="Real-time network traffic analysis",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── REST endpoints ────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    running = sniffer_proc is not None and sniffer_proc.poll() is None
    return {"status": "ok" if running else "sniffer_down",
            "sniffer_running": running,
            "interface": INTERFACE}


@app.get("/api/metrics")
async def get_metrics(window: int = Query(0, description="Seconds (0=all)")):
    async with get_db() as db:
        metrics   = await query_metrics(db, window)
        latest    = await query_latest_stats(db)
        timeseries = await query_timeseries(db, seconds=60)

    return {
        "metrics":    metrics,
        "latest_stats": latest,
        "timeseries": timeseries,
    }


@app.get("/api/flows")
async def get_flows(limit: int = Query(100, le=1000)):
    async with get_db() as db:
        flows = await query_flows(db, limit)
    return {"flows": flows, "count": len(flows)}


@app.get("/api/protocols")
async def get_protocols():
    async with get_db() as db:
        metrics = await query_metrics(db)
    total = metrics.get("total_packets") or 1
    protos = metrics.get("protocols", {})
    return {
        "protocols": [
            {
                "protocol": k,
                "count": v,
                "pct": round(100.0 * v / total, 1),
            }
            for k, v in sorted(protos.items(),
                                key=lambda x: x[1], reverse=True)
        ],
        "total_packets": total,
    }


@app.get("/api/top-talkers")
async def get_top_talkers(limit: int = Query(10, le=100)):
    async with get_db() as db:
        talkers = await query_top_talkers(db, limit)
    return {"top_talkers": talkers}


@app.get("/api/packets")
async def get_packets(
    limit: int = Query(50, le=500),
    protocol: Optional[str] = Query(None),
):
    async with get_db() as db:
        packets = await query_recent_packets(db, limit, protocol)
    return {"packets": packets, "count": len(packets)}


# ── WebSocket ─────────────────────────────────────────────────────────────

@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    await manager.connect(websocket)
    log.info("WebSocket client connected (%d total)",
             len(manager.active))
    try:
        while True:
            # Keep connection alive; all data is pushed via broadcast()
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        log.info("WebSocket client disconnected (%d remaining)",
                 len(manager.active))
