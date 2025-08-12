from __future__ import annotations
from typing import List

# Basit wildcard arayıcı: pattern: "E8 ?? ?? 90"

def parse_pattern(pat: str) -> List[int | None]:
    out = []
    for tok in pat.strip().split():
        if tok == "??":
            out.append(None)
        else:
            out.append(int(tok, 16))
    return out

def find_pattern(data: bytes, pat: str) -> list[int]:
    p = parse_pattern(pat)
    m = len(p)
    hits = []
    for i in range(0, len(data) - m + 1):
        ok = True
        for j, want in enumerate(p):
            if want is None:
                continue
            if data[i+j] != want:
                ok = False; break
        if ok:
            hits.append(i)
    return hits
