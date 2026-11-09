"""FastAPI backend + dashboard host."""
import asyncio
import json
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from .engine import Attack, UDP_METHODS, probe

app = FastAPI(title="MC Stress Console")
STATE = {"attack": None, "task": None, "log": []}
STATIC = Path(__file__).parent / "static"


def log(msg):
    STATE["log"].append({"t": time.strftime("%H:%M:%S"), "m": str(msg)})
    del STATE["log"][:-200]


class StartReq(BaseModel):
    target: str
    port: Optional[int] = None
    method: str = "status"
    concurrency: int = 300
    duration: int = 60
    timeout: float = 5.0
    hold: float = 0.0


@app.get("/", response_class=HTMLResponse)
async def index():
    return (STATIC / "index.html").read_text(encoding="utf-8")


@app.post("/api/start")
async def start(req: StartReq):
    cur = STATE["attack"]
    if cur and cur.running:
        raise HTTPException(409, "an attack is already running")
    a = Attack(
        req.target, req.port, req.method, req.concurrency,
        req.duration, req.timeout, req.hold,
    )
    try:
        host, port = await a.resolve()
    except Exception as e:
        raise HTTPException(400, f"resolve failed: {e}")
    STATE["attack"] = a

    async def runner():
        try:
            await a.run()
        except Exception as e:
            log(f"fatal: {e}")
        log("finished")

    STATE["task"] = asyncio.create_task(runner())
    log(f"START {req.method} -> {host}:{port} conc={a.concurrency} dur={a.duration}s")
    return {"ok": True, "host": host, "port": port}


@app.post("/api/stop")
async def stop():
    a = STATE["attack"]
    if not a:
        return {"ok": False, "reason": "idle"}
    await a.stop()
    log("stopped by user")
    return {"ok": True}


@app.get("/api/stats")
async def stats():
    a = STATE["attack"]
    if not a:
        return {"idle": True}
    d = a.stats.snapshot()
    d.update(
        idle=False, running=a.running, method=a.method,
        target=a.hostname, port=a.port,
    )
    return d


@app.get("/api/log")
async def get_log():
    return STATE["log"]


@app.get("/api/probe")
async def api_probe(target: str, port: int = 25565):
    try:
        return await probe(target, port)
    except Exception as e:
        raise HTTPException(400, f"probe failed: {e}")


@app.get("/api/stream")
async def stream():
    async def gen():
        while True:
            a = STATE["attack"]
            if not a:
                yield "data: " + json.dumps({"idle": True}) + "\n\n"
            else:
                d = a.stats.snapshot()
                d.update(
                    idle=False, running=a.running, method=a.method,
                    target=a.hostname, port=a.port,
                )
                yield "data: " + json.dumps(d) + "\n\n"
            await asyncio.sleep(0.5)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )