"""Minecraft protocol primitives: VarInt, handshake, status, login, Bedrock ping."""
import random
import struct

MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")
ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def varint(n: int) -> bytes:
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


def read_varint(buf: bytes, offset: int = 0):
    val = 0
    shift = 0
    while True:
        if offset >= len(buf):
            raise ValueError("eof")
        b = buf[offset]
        offset += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, offset
        shift += 7
        if shift > 35:
            raise ValueError("varint too big")


def mcstring(s: str) -> bytes:
    b = s.encode("utf-8")
    return varint(len(b)) + b


def packet(pid: int, payload: bytes = b"") -> bytes:
    body = varint(pid) + payload
    return varint(len(body)) + body


def handshake(host: str, port: int, next_state: int, protocol: int = -1) -> bytes:
    return packet(
        0x00,
        varint(protocol)
        + mcstring(host)
        + struct.pack(">H", port & 0xFFFF)
        + varint(next_state),
    )


def status_request() -> bytes:
    return packet(0x00)


def status_ping(ts: int = 0) -> bytes:
    return packet(0x01, struct.pack(">q", ts))


def login_start(name: str) -> bytes:
    return packet(0x00, mcstring(name))


def bedrock_ping() -> bytes:
    return (
        b"\x01"
        + struct.pack(">Q", random.getrandbits(63))
        + MAGIC
        + struct.pack(">Q", random.getrandbits(64))
    )


def random_name(n: int = 8) -> str:
    return "".join(random.choices(ALPHABET, k=n))