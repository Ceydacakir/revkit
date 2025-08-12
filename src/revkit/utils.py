from __future__ import annotations
import math
import os
from typing import Iterable, Tuple

MAGICS = {
    b"\x7fELF": "ELF",
    b"MZ": "PE",
    b"\xcf\xfa\xed\xfe": "Mach-O",
    b"\xfe\xed\xfa\xcf": "Mach-O",
}

def magic(path: str) -> str:
    with open(path, "rb") as f:
        head = f.read(4)
    for sig, name in MAGICS.items():
        if head.startswith(sig):
            return name
    return "Unknown"

def iter_strings(data: bytes, min_len: int = 4) -> Iterable[Tuple[int, str]]:
    # ASCII
    s, start = [], None
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if start is None:
                start = i
            s.append(chr(b))
        else:
            if start is not None and len(s) >= min_len:
                yield start, "".join(s)
            s, start = [], None
    if start is not None and len(s) >= min_len:
        yield start, "".join(s)

    # UTF-16-LE/basic
    try:
        text = data.decode("utf-16le", errors="ignore")
        off = 0
        run, rstart = [], None
        for ch in text:
            if ch.isprintable() and ch not in "\r\n\t\x0b\x0c":
                if rstart is None:
                    rstart = off
                run.append(ch)
            else:
                if rstart is not None and len(run) >= min_len:
                    yield rstart*2, "".join(run)
                run, rstart = [], None
            off += 1
        if rstart is not None and len(run) >= min_len:
            yield rstart*2, "".join(run)
    except Exception:
        pass

def calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0]*256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c/n
            ent -= p * math.log2(p)
    return ent
